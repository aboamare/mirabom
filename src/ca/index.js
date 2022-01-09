const dayjs = require('dayjs')
const uuid = require('uuid').v4

const { crypto, MCPCertificate } = require('./certificate')
const { OCSPRequest, OCSPResponse } = require('./ocsp')
const DB = require('../db')()

class CertificateAuthority extends Object {
  constructor (organization) {
    super()
    Object.assign(this, organization)

    if (!this.crl && this.domain && this.ipid) {
      this.crl = `https://${this.domain}/${this.ipid}/crl`
    }
    if (!this.ocsp && this.domain && this.ipid) {
      this.ocsp = `https://${this.domain}/${this.ipid}/ocsp`
    }

  }

  get DN () {
    return this._dn || { UID: this.UID }
  }

  set DN (obj) {
    this._dn = obj
  }

  _SAN (entity, fields = ['commonName', 'organization', 'country', 'emailAddress', 'flagState', 'callSign', 'IMONumber', 'MMSI', 'shipType', 'homePort', 'secondaryMRN', 'URL']) {
    return fields.reduce((san, field) => {
      const value = entity[field]
      if (!!value) {
        san[field] = value
      } 
      return san
    }, {})
  }

  _createSubject (entity, type = 'entity') {
    /*
     * Return an Object with all the properties needed to populate a certificate for the given entity.
     */
    const types = {
      entity: obj => {
        return Object.assign(
          {
            DN: { UID: obj.UID || `${this.UID}:${uuid()}` },
            SAN: this._SAN(obj),
            keyUsage: ['digitalSignature', 'anyKeyUsage', 'clientAuth'],
            crl: obj.crl || this.crl,
            ocsp: obj.ocsp || this.ocsp
          }, 
          obj
        )
      },
      mir: obj => {
        return Object.assign(
          {
            DN: { UID: obj.UID || `urn:mrn:mcp:id:${obj.ipid || obj.organization}` },
            SAN: this._SAN({
              name: obj.name || obj.id,
              organization: obj.organization || obj.ipid,
              unit: obj.unit,
              country: obj.country,
              email: obj.email,
              URL: obj.url
            }),
            basicConstraints: {cA: true, pathLenConstraint: 4},
            keyUsage: ['digitalSignature', 'keyCertSign', 'clientAuth'],
            crl: obj.crl || `https://${obj.domain}/${obj.ipid}/crl`,
            ocsp: obj.ocsp || `https://${obj.domain}/${obj.ipid}/ocsp`
          },
          obj
        )
      },
      root: obj => {
        return Object.assign(
          {
            DN: {
              organization: obj.organization || obj.ipid,
              country: obj.country,
              email: obj.email
            },
            SAN: this._SAN({
              URL: obj.url || `https://${obj.domain}`,
            }),
            basicConstraints: {cA: true, pathLenConstraint: 4},
            keyUsage: ['keyCertSign'],
          },
          obj
        )
      }
    }
    return types[type](entity)
  }
  
  async _createKey (namedCurve = 'P-384') {
    try {
      const keyPair = await crypto.generateKey(
        {
          name: "ECDSA",
          namedCurve 
        },
        true,
        ["sign", "verify"]
      )
      const jwkPair = {}
      jwkPair.private = await crypto.exportKey('jwk', keyPair.privateKey)
      jwkPair.public = await crypto.exportKey('jwk', keyPair.publicKey)
      console.debug(jwkPair)
      return jwkPair
    } catch (err) {
      console.error(err)
    }
  }

  async _useKey (keyPair) {
    this.public = keyPair.public
    // ensure that the private key is ready to use for signing
    this.private = await crypto.importKey('jwk', keyPair.private, {name: 'ECDSA', namedCurve: keyPair.private.crv}, keyPair.private.ext, keyPair.private.key_ops)
    this.fingerprint = keyPair._id
  }

  async _getKey (fingerprint) {
    return DB.keys.findOne({_id: fingerprint || this.certificates[0]})
  }

  async _loadPrivateKey () {
    const keyPair = await this._getKey()
    await this._useKey(keyPair)
    this.algorithm = "SHA-384"
  }

  async _loadOwnPEM () {
    const cert = await DB.certificates.findOne({ _id: this.certificates[0] })
    this.pem = cert.pem, 
    this.fingerprint = cert._id
  }

  async _createCertificate (subject, days = 731, algorithm = "SHA-384" ) {
    try {
      const cert = new MCPCertificate(subject)
      cert.setIssuer(this.DN)
      cert.notBefore.value = new Date()
      cert.notAfter.value = dayjs().add(days, 'days').toDate()
      cert.subjectPublicKeyInfo.fromJSON(subject.public)
      await cert.setSubjectKeyIdentifier()
      await cert.setAuthorityKeyIdentifier(this)
      
      cert.setKeyUsage(subject.keyUsage)
      if (subject.basicConstraints) {
        cert.setBasicConstraints(subject.basicConstraints)
      }
      if (subject.crl) {
        cert.setCRLDistributionPoints([subject.crl])
      }
      if (subject.ocsp) {
        cert.setOCSP(subject.ocsp)
      }

      await cert.sign(this.private, algorithm)

      const fingerprint = await cert.fingerprint()
      let certificateBuffer = await cert.toSchema(true).toBER(false)
      certificateBuffer = Buffer.from(certificateBuffer).toString('base64')

      return {
        _id: fingerprint,
        mrn: subject.DN.UID || 'root',
        notAfter: cert.notAfter.value,
        pem: `-----BEGIN CERTIFICATE-----\n${certificateBuffer.replace(/(.{64})(?!$)/g, '$1\n')}\n-----END CERTIFICATE-----\n`,
        serial: cert.serial
      }
    } catch (err) {
      console.log(err)
      throw err
    }
  }

  async getCertificateChain (fingerprint) {
    let next = fingerprint
    let chain = []
    while (next) {
      const cert = await DB.certificates.findOne({ _id: next })
      if (cert) {
        chain.push(cert)
        next = cert.parent
      } else {
        next = null
      }
    }
    return chain
  }

  async issueCertificate (entity, type = 'entity', days = 731) {
    // make sure this CA has its private key
    if (!this.private) {
      const keyPair = await this._getKey()
      await this._useKey(keyPair)
    }

    // prepare the entity as subject for a certificate
    const subject = this._createSubject(entity, type)
    if (!subject.public) {
      const keyPair = await this._createKey()
      Object.assign(subject, keyPair)
    }

    // issue a fresh certificate
    // TODO: check that expiration is before the expiration of the cert used by this CA
    const cert = await this._createCertificate(subject, days)
    cert.parent = this.fingerprint
    await DB.certificates.insert(cert)
    console.debug(`Issued certificate ${cert.id} to ${subject.DN}`)
    console.debug(cert.pem)

    // if a new keypair was created for the entity save it
    if (subject.private) {
      await DB.keys.insert({
        _id: cert._id,
        private: subject.private,
        public: subject.public
      })
    }

    // update the entity with the new DN (i.e. mrn), cert, etc.
    Object.assign (entity, subject.DN)
    if (! Array.isArray(entity.certificates)) {
      entity.certificates = []
    }
    entity.certificates.unshift(cert._id)
    entity.certificateExpires = cert.notAfter
  }

  async responseForOCSPRequest (buffer) {
    const req = new OCSPRequest(buffer, this.UID)
    const reqCerts = new Map(req.serials.map(s => [s, undefined]))
    const foundCerts = await DB.certificates.find({ serial: {$in: [...reqCerts.keys()]} }, { serial: 1, status: 1, _id: 0})
    const statuses = (foundCerts || []).reduce((obj, cert) => {
      obj[cert.serial] = cert.status || 'good'
    }, {})
    await this._loadOwnPEM()
    const resp = OCSPResponse.to(req, this, statuses)
    await this._loadPrivateKey()
    return await resp.toDER()
  }

  static async initialize (config) {
    let root = {
      ipid: config.ipid,
      domain: config.domain,
      country: config.country,
      email: config.admin || `mir-admin@${config.domain}`
    }
    const mir = Object.assign(
      root,
      {
        email: config.email || `mir@${config.domain}`,
        URL: config.url || `https://${config.domain}/${config.ipid}.html`
      }
    )

    const rootCA = new CertificateAuthority(root)
    const rootKey = await rootCA._createKey()
    await rootCA._useKey(rootKey)
    root = rootCA._createSubject(root, 'root')
    root.public = rootKey.public
    rootCA.DN = root.DN // create a self-signed cert
    const rootCert = await rootCA._createCertificate(root, 10 * 365 + 2)
    rootKey._id = rootCert._id
    await DB.certificates.insert(rootCert)
    await DB.keys.insert(rootKey)

    await rootCA.issueCertificate(mir, 'mir', 5 * 365 + 1)
    mir.root = rootCert._id
    return mir
  }
}

module.exports = {
  CertificateAuthority
}

