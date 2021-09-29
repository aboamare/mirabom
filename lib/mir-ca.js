const { exit } = require('process')
const { exec } = require('child_process')
const fs = require('fs').promises
const { dir } = require('tmp-promise')
const tmp = require('tmp')

const sslConf = require('./openssl-config')

const DB = require('./db')(async (db) => {
  db.ready = true
  await test()
  exit()
})

const Config = {
  ipid: 'aboamare',
  country: 'FI',
  domain: 'abaamare.net'
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
    conf: 'cfg'
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

async function _getRootCertificate() {
  let cert = DB.getCertificate(Config.ipid)
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

async function _createRootCertificate(serial=1) {
  try {
    const id = `${Config.ipid}_root`
    Config.mrn = Config.mrn || `urn:mrn:mcp:mir:${Config.ipid || 'aboamare'}:self`
    const conf = sslConf.forRootCert(Config)
    const configFile = await _tmpFile('conf', id, conf)
    const keyFile = await _getKeyFile(id)
    const pem = await OpenSSL('req', [
      '-new',
      '-x509',
      '-utf8',
      '-days 731',
      `-config ${configFile}`,
      `-key ${keyFile}`,
      `-set_serial ${serial}`
    ])
    await fs.unlink(configFile)
    await fs.unlink(keyFile)
    DB.saveCertificate(id, pem)
    return pem
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
  const pem = await _getRootCertificate()
  const txt = await parseCertificate(pem, `${Config.ipid}_root`)
  console.log(txt)
}
