const { exit } = require('process')
const { exec } = require('child_process')
const fs = require('fs').promises
const { dir } = require('tmp-promise')
const tmp = require('tmp')

const oid = require('./mcp-oids')
const sslConf = require('./openssl-config')

const DB = require('./db')(async (db) => {
  db.ready = true
  await test()
  exit()
})

const Config = {
  ipid: 'aboamare',
  country: 'FI',
  domain: 'mir.aboamare.net'
}

let TmpDir = null

tmp.setGracefulCleanup()

async function _ensureTmpDir (parentDirPath) {
  TmpDir = await dir({tmpdir: parentDirPath, unsafeCleanup: true})
  console.info(`Created directory for temporary files: ${TmpDir.path}`)
}

function _getPath(type, id) {
  fileTypes = {
    key: 'pem',
    cert: 'pem',
    conf: 'cfg',
    csr: 'csr'
  }
  return `${TmpDir.path}/_${type}_${id.replace(/[:]/, '_')}.${fileTypes[type] || txt}`
}

async function file (type, id, flags='w') {
  const path = _getPath(type, id)
  const fh = await fs.open(path, flags)
  return {fh, path}
}

function OpenSSL (cmd = 'genpkey', options = []) {
  // exceutue given openssl command and return the result as printed on stdout
  const bin = process.env['OPENSSL_PATH'] || '/usr/local/opt/openssl/bin/openssl'
  options.unshift(cmd)
  return new Promise((resolve, reject) => {
    try {
      exec(`${bin} ${options.join(' ')}`, (err, stdout, stderr) => {
        if (err) {
          console.log(stderr)
          reject(err)
        }
        resolve(stdout)
      })
    } catch (err) {
      console.error(err)
      reject(null)
    }
  })
}

async function _tmpFile(type, id, content) {
  const {fh, path} = await file(type, id)
  fh.writeFile(content, {encoding: 'utf8'})
  await fh.close()
  return path

}

async function _createKey(id) {
  try {
    const pem = await OpenSSL('genpkey', [
      '-algorithm EC',
      '-pkeyopt ec_paramgen_curve:P-256'
    ])
    console.log(pem)
    DB.saveKey(id, pem)
    return pem
  } catch (err) {
    console.error(err)
  }
}

async function _getKeyFile(id) {
  let key = DB.getKey(id)
  if (!key) {
    key = await _createKey(id)
  } else {
    key = key.pem
  }
  const path = await _tmpFile('key', id, key)
  return path
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
  mir: obj => {
    const MRN = obj.mrn || `urn:mrn:mcp:mir:${obj.ipid}:ca`
    Object.assign(obj, Object.assign({
      type: 'mir',
      dnFields: ['CN', 'O', 'OU', 'C', 'emailAddress', 'UID'],
      CN: obj.ipid,
      O: obj.ou || obj.ipid,
      OU: obj.type || 'mir',
      C: obj.country || Config.country,
      emailAddress: obj.email || `mir@${obj.domain || Config.domain}`,
      MRN,
      UID: MRN},
      obj))
    obj.san = obj.san || _SAN(['MRN'], obj) 
  }
}

function ensurePropertiesFor(type='vessel', entity) {
  /*
   * Ensure that a given obj has all the properties needed to populate a certificate for the given type.
   */
  entity.type = type
  _ensurePropertiesFor[type](entity)
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
    const root = Object.assign({
      id: `${Config.ipid}_root`,
      mrn: `urn:mrn:mcp:mir:${Config.ipid || 'aboamare'}:self`
    }, Config)
    ensurePropertiesFor('mir', root)
    const conf = sslConf.forRootCert(root)
    const configFile = await _tmpFile('conf', root.id, conf)
    const keyFile = await _getKeyFile(root.id)
    const pem = await OpenSSL('req', [
      '-new',
      '-x509',
      '-utf8',
      '-days 3655',
      `-config ${configFile}`,
      `-key ${keyFile}`,
      `-set_serial ${serial}`,
    ])
    await fs.unlink(configFile)
    await fs.unlink(keyFile)
    DB.saveCertificate(root.id, pem)
    return pem
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
  await _ensureTmpDir(process.env['MIR_TMP_DIR'] || '.')
  //const pem = await fs.readFile('../test.csr')
  const csr = await createCAcsr()
  // sign the CSR with our own root certificate, so ensure we have a root cert
  await _getRootCertificate()
  const cert = await _issueCertificate(csr, Date.now(), 'root')
  const txt = await parseCertificate(cert, csr.id)
  console.log(txt)
}
