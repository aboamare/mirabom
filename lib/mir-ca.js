const { exit } = require('process')

const webcrypto = require('crypto').webcrypto
const dayjs = require('dayjs')
const asn1 = require('asn1js')
const pki = require('pkijs')
const oid = require('./mcp-oids')
const uuid = require('uuid').v4

const crypto = new pki.CryptoEngine({name: "node", crypto: webcrypto, subtle: webcrypto.subtle})
pki.setEngine("node", webcrypto, crypto)

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

async function _createKey(id, namedCurve = 'P-256') {
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
  } else {
    keyPair.private = await crypto.importKey('jwk', keyPair.private, {name: 'ECDSA', namedCurve: keyPair.private.crv}, keyPair.private.ext, keyPair.private.key_ops)
    keyPair.public = await crypto.importKey('jwk', keyPair.public, {name: 'ECDSA', namedCurve: keyPair.public.crv}, keyPair.public.ext, keyPair.public.key_ops)
  }
  return keyPair
}

async function _getCertFile(id) {
  let cert = DB.getCertificate(id)
  if (!cert) {
    return undefined
  }
  const path = await _tmpFile('cert', id, cert.pem)
  return path
}

async function _getRootCertificate() {
  let cert = DB.getCertificate(`${Config.ipid}_root`)
  if (!cert) {
    cert = await _createRootCertificate()
  } else {
    cert = cert.pem
  }
  return cert
}

function _setIssuer(cert, obj) {
  cert.issuer.typesAndValues.push(...Object.keys(obj).map(attr => {
    return new pki.AttributeTypeAndValue({type: oid[attr], value: new asn1.PrintableString({ value: obj[attr]})})
  }))
}

function _setDN(cert, obj) {
  cert.subject.typesAndValues.push(...Object.keys(obj).map(attr => {
    return new pki.AttributeTypeAndValue({type: oid[attr], value: new asn1.PrintableString({ value: obj[attr]})})
  }))
}

function _setBasicConstraints(cert, obj = {cA: true, pathLenConstraint: 4}) {
  const basicConstr = new pki.BasicConstraints(obj)  
  cert.extensions.push(new pki.Extension({
    extnID: "2.5.29.19",
    critical: false,
    extnValue: basicConstr.toSchema().toBER(false),
    parsedValue: basicConstr
}))}

function _setKeyUsage(cert, keyUses = ['digitalSignature', 'any']) {
  const bitArray = new ArrayBuffer(1)
  const bitView = new Uint8Array(bitArray)

  if (keyUses.includes('digitalSignature'))   bitView[0] |= (1 << 7)
  // if (keyUses.includes('contentCommitment'))  bitView[0] |= (1 << 6)
  if (keyUses.includes('keyEncipherment'))    bitView[0] |= (1 << 5)
  if (keyUses.includes('dataEncipherment'))   bitView[0] |= (1 << 4)
  if (keyUses.includes('keyAgreement'))       bitView[0] |= (1 << 3)
  if (keyUses.includes('keyCertSign'))        bitView[0] |= (1 << 2)
  // if (keyUses.includes('bj.encipherOnly'))    bitView[0] |= (1 << 0)
  // if (keyUses.includes('decipherOnly'))       bitView[0] |= (1 << 15)
  
  const keyUsage = new asn1.BitString({ valueHex: bitArray })
  
  cert.extensions.push(new pki.Extension({
      extnID: "2.5.29.15",
      critical: false,
      extnValue: keyUsage.toBER(false),
      parsedValue: keyUsage
    })
  )

  const extKeyUsage = new pki.ExtKeyUsage({
		keyPurposes: keyUses.map(usage => oid[usage]).filter(use => !!use)
	})
	if (extKeyUsage && extKeyUsage.length) {
    cert.extensions.push(new pki.Extension({
        extnID: "2.5.29.37",
        critical: false,
        extnValue: extKeyUsage.toSchema().toBER(false),
        parsedValue: extKeyUsage // Parsed value for well-known extensions
      })
    )
  }
}

async function parseCertificate(pem, id) {
  const certFile = await _tmpFile('cert', id, pem)
  const text = await OpenSSL('x509', [
    `-in ${certFile}`,
    '-text'
  ])
  await fs.unlink(certFile)
  return text
}

async function parseCSR(pem, id, csr=true) {
  const certFile = await _tmpFile('cert', id, pem)
  const text = await OpenSSL('req', [
    `-in ${certFile}`,
    '-text'
  ])
  await fs.unlink(certFile)
  return text
}

function _getReqId(csr) {
  return csr.$loki
}

function _SAN(fields=['MRN'], obj) {
  return fields.map(field => {
    if (! (oid[field] && obj[field])) {
      return false
    }
    return `otherName:${oid[field]};UTF8:${obj[field]}`
  }).filter(v => v)
  .join(',')
}

const _ensurePropertiesFor = {
  device: obj => {
    const MRN = obj.mrn || `urn:mrn:mcp:${obj.ipid}:${uuid()}`
    Object.assign({
      type: 'device',
      dnFields: ['UID'],
      O: obj.organization
    }, obj)
  },
  mir: obj => {
    const domain = obj.domain || Config.domain
    const MRN = obj.mrn || `urn:mrn:mcp:${obj.ipid}:ca`
    Object.assign(obj, Object.assign({
      type: 'mir',
      dnFields: ['UID'],
      CN: obj.ipid,
      O: obj.organization || obj.ipid,
      OU: obj.type || 'mir',
      C: obj.country || Config.country,
      emailAddress: obj.email || `mir@${domain}`,
      UID: MRN,
      URL: obj.url || `https://${domain}/mir.json`},
      obj))
    obj.san = obj.san || _SAN(['CN', 'O', 'OU', 'C', 'emailAddress'], obj) 
  },
  root: obj => {
    const domain = obj.domain || Config.domain
    Object.assign(obj, Object.assign(
      {
        DN: {
          O: obj.organization || obj.ipid,
          C: obj.country || Config.country,
          emailAddress: obj.email || `mir@${domain}`
        },
        URL: obj.url || `https://${domain}`,
        basicConstraints: {cA: true, pathLenConstraint: 4},
        keyUsage: ['keyCertSign']
      },
      obj))
    obj.san = obj.san || _SAN(['URL'], obj) 
  }
}

function ensurePropertiesFor(type='vessel', entity) {
  /*
   * Ensure that a given obj has all the properties needed to populate a certificate for the given type.
   */
  entity.type = type
  _ensurePropertiesFor[type](entity)
}

async function _createCertificate(subject, issuer, days=731, version=2) {
  const cert = new pki.Certificate()
  cert.version = version
  cert.serialNumber = new asn1.Integer({ value: Date.now() })
  _setIssuer(cert, issuer.DN)
  _setDN(cert, subject.DN)
  cert.notBefore.value = new Date()
  cert.notAfter.value = dayjs().add(days, 'days').toDate()
  cert.extensions = []
  _setBasicConstraints(cert, subject.basicConstraints)
  _setKeyUsage(cert, subject.keyUsage)
  await cert.subjectPublicKeyInfo.importKey(subject.public)
  await cert.sign(issuer.private, "SHA-256")

  // convert to PEM
  let certificateBuffer = await cert.toSchema(true).toBER(false)
  certificateBuffer = Buffer.from(certificateBuffer)
		
  let pem = "-----BEGIN CERTIFICATE-----\r\n"
  pem = `${pem}${certificateBuffer.toString('base64').replace(/(.{64})/g, '$1\n')}`
  pem = `${pem}\r\n-----END CERTIFICATE-----\r\n`
  return pem
}

async function _issueCertificate(csr, serial=undefined, caCertId='ca', trusted=false) {
  try {
    const id = csr.id
    const reqFile = await _tmpFile('csr', id, csr.pem)
    const caId = `${Config.ipid}_${caCertId}`
    const configFile = await _tmpFile('conf', id, id.endsWith('ca') ? sslConf.forCAcert(csr) : sslConf.forIssuedCert(csr))
    const caKeyFile = await _getKeyFile(caId)
    const caCertFile = await _getCertFile(caId)
    const options = [
      '-req',
      `-in ${reqFile}`,
      `-extfile ${configFile}`,
      `-CAkey ${caKeyFile}`,
      `-CA ${caCertFile}`,
      `-set_serial ${serial || Date.now()}`,
      `-days ${id.endsWith('ca') ? '1827' : '731'}`
    ]
    const pem = await OpenSSL('x509', options)
    await fs.unlink(configFile)
    await fs.unlink(caKeyFile)
    DB.saveCertificate(id, pem)
    return pem
  } catch (err) {
    console.error(err)
  }
}

async function _createRootCertificate(serial=1) {
  try {
    const root = Object.assign({id: `${Config.ipid}_root`}, Config)
    ensurePropertiesFor('root', root)
    const keyPair = await _getKey(root.id, 'P-384')
    Object.assign(root, keyPair)
    const cert = await _createCertificate(root, root)
    // const pem = await OpenSSL('req', [
    //   '-new',
    //   '-x509',
    //   '-utf8',
    //   '-days 3655',
    //   `-config ${configFile}`,
    //   `-key ${keyFile}`,
    //   `-set_serial ${serial}`,
    // ])
    // DB.saveCertificate(root.id, pem)
    // return pem
    return cert
  } catch (err) {
    console.error(err)
  }
}

async function createCSR(type, entity) {
  try {
    ensurePropertiesFor(type, entity)
    const conf = sslConf.forCSR(entity)
    const configFile = await _tmpFile('conf', entity.id, conf)
    let pem = entity.pem
    if (!pem) {
      const keyFile = await _getKeyFile(entity.id)
      pem = await OpenSSL('req', [
        '-new',
        '-utf8',
        `-config ${configFile}`,
        `-key ${keyFile}`
      ])
      await fs.unlink(keyFile)
    }
    await fs.unlink(configFile)
    const csrObj = DB.addCSR(pem, entity)
    return csrObj
  } catch (err) {
    console.error(err)
  }

}
async function createCAcsr() {
  try {
    const ca = Object.assign({
        id: `${Config.ipid}_ca`,
        ipid: Config.ipid || 'aboamare',
        mrn: `urn:mrn:mcp:mir:${Config.ipid || 'aboamare'}:ca`
      }, Config)
    const csrObj = await createCSR('mir', ca)
    return csrObj
  } catch (err) {
    console.error(err)
  }
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
  const pem = await _getRootCertificate()
  console.debug(pem)
  //const cert = await _issueCertificate(csr, Date.now())
  //const txt = await parseCertificate(cert, csr.id)
  //console.log(txt)
}
