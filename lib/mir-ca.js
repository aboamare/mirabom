const { exit } = require('process')
const uuid = require('uuid').v4

const { crypto, MCPCertificate } = require('./certificate')

const DB = require('./db')(async (db) => {
  db.ready = true
  try {
    await test()
  } catch (err) {
    console.error(err)
  }
  db.saveDatabase(err => {
    if (err) console.error(err)
    exit()
  })
})

const Config = {
  ipid: 'aboamare',
  country: 'FI',
  domain: 'mir.aboamare.net'
}

function _SAN (entity, fields = ['commonName', 'organization', 'country', 'emailAddress', 'flagState', 'callSign', 'IMONumber', 'MMSI', 'shipType', 'homePort', 'secondaryMRN', 'URL']) {
  entity.san = fields.reduce((san, field) => {
    const value = entity[field]
    if (!!value) {
      san[field] = value
    } 
    return san
  }, {})
}

const _ensurePropertiesFor = {
  entity: obj => {
    const mrn = obj.mrn || `urn:mrn:mcp:${obj.ipid}:${uuid()}`
    Object.assign(obj, Object.assign(
      {
        DN: { UID: mrn },
        SAN: _SAN (obj),
        keyUsage: ['digitalSignature', 'anyKeyUsage', 'clientAuth'],
      }, 
    obj))
  },
  mir: obj => {
    const domain = obj.domain || Config.domain
    const mrn = obj.mrn || obj.id
    Object.assign(obj, Object.assign(
      {
        DN: { UID: mrn },
        SAN: {
          name: obj.ipid,
          organization: obj.organization || obj.ipid,
          country: obj.country || Config.country,
          email: obj.email || `mir@${domain}`,
          URL: obj.url || `https://${domain}/mir.json`
        },
        basicConstraints: {cA: true, pathLenConstraint: 4},
        keyUsage: ['digitalSignature', 'keyCertSign', 'clientAuth'],
        crl: obj.crl || `https://${domain}/crl`,
        ocsp: obj.ocsp || `https://${domain}/ocsp`
    },
    obj))
  },
  root: obj => {
    const domain = obj.domain || Config.domain
    Object.assign(obj, Object.assign(
      {
        DN: {
          organization: obj.organization || obj.ipid,
          country: obj.country || Config.country,
          email: obj.email || `mir-admin@${domain}`
        },
        SAN: {
          URL: obj.url || `https://${domain}`,
        },
        basicConstraints: {cA: true, pathLenConstraint: 4},
        keyUsage: ['keyCertSign'],
      },
      obj))
  }
}

function ensurePropertiesFor(entity) {
  /*
   * Ensure that a given obj has all the properties needed to populate a certificate for the given type.
   */
  _ensurePropertiesFor[entity.type](entity)
}

async function _createKey(id, namedCurve = 'P-384') {
  try {
    const keyPair = await crypto.generateKey(
      {
        name: "ECDSA",
        namedCurve 
      },
      true,
      ["sign", "verify"]
    )
    const jwkPair = {id}
    jwkPair.private = await crypto.exportKey('jwk', keyPair.privateKey)
    jwkPair.public = await crypto.exportKey('jwk', keyPair.publicKey)
    console.log(jwkPair)
    DB.saveKey(jwkPair)
    return jwkPair
  } catch (err) {
    console.error(err)
  }
}

async function _getKey(id) {
  let keyPair = DB.getKey(id)
  if (!keyPair) {
    keyPair = await _createKey(id)
  }
  // ensure that the private key is ready to use for signing
  keyPair.private = await crypto.importKey('jwk', keyPair.private, {name: 'ECDSA', namedCurve: keyPair.private.crv}, keyPair.private.ext, keyPair.private.key_ops)
  return keyPair
}

async function _getCertificate(entity, issuerId = 'mir') {
  let issuer
  if (!entity) { // get the root certificate
    entity = Object.assign({id: Config.ipid, type: 'root'}, Config)
    issuer = entity
  } else if (entity === 'mir') {
    entity = Object.assign({id: `urn:mrn:mcp:id:${Config.ipid}`, type: 'mir'}, Config)
    issuerId = null
  } else if (typeof entity === 'string') {
    entity = {id: entity}
  }

  let id = typeof entity === 'string' ? entity : (entity || {id: undefined}).id
  if (id) {
    let cert = DB.getCertificate(id)
    if (cert) {
      Object.assign(entity, cert)
      return entity
    } 
  } else if (typeof entity !== 'object') {
    return undefined
  }

  // issue a new cert for the given entity
  if (!issuer) {
    issuer = await _getCertificate(issuerId)
  }
  if (!entity.type) {
    entity.type = 'entity'
  }
  ensurePropertiesFor(entity)
  const keyPair = await _getKey(entity.id)
  Object.assign(entity, keyPair)
  await MCPCertificate.issue(entity, issuer)
  DB.saveCertificate(entity)
  console.debug(entity.pem)
  return entity
}

module.exports = (config = {ipid: 'aboamare'}) => {
  Object.assign(Config, config)
  return {
    createRootCertificate
  }
}

async function test () {
  //const pem = await fs.readFile('../test.csr')
  //const csr = await createCSR('device', {pem})
  //const csr = await createCAcsr()
  // sign the CSR with our own root certificate, so ensure we have a root cert
  const mir = await _getCertificate('mir')
  //const cert = await _issueCertificate(csr, Date.now())
  //const txt = await parseCertificate(cert, csr.id)
  //console.log(txt)
}
