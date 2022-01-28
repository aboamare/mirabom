import dayjs from 'dayjs'
import { v4 as uuid } from 'uuid'

import { getCrypto, MCPCertificate } from './certificate.js'
import  { MCPEntity } from 'mirau'
import { OCSPRequest, OCSPResponse } from './ocsp.js'

import db from'../db/index.js'
const DB = db()

export class CertificateAuthority extends Object {
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
    return this._dn || { uid: this.uid }
  }

  set DN (obj) {
    this._dn = obj
  }

  _SAN (entity, fields = [...MCPEntity.RecognizedProperties]) {
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
            DN: { uid: obj.uid || `${this.uid}:${uuid()}` },
            SAN: this._SAN(obj),
            keyUsage: ['digitalSignature', 'anyKeyUsage', 'clientAuth'],
            crl: obj.crl || this.crl,
            ocsp: obj.ocsp || this.ocsp,
            x5u: cert => `https://${this.domain}/${this.ipid}/certificates/${cert.serial}.x5u`
          }, 
          obj
        )
      },
      mir: obj => {
        return Object.assign(
          {
            DN: { uid: obj.uid || `urn:mrn:mcp:id:${obj.ipid || obj.organization}` },
            SAN: this._SAN({
              name: obj.name || obj.id,
              organization: obj.organization || obj.ipid,
              unit: obj.unit,
              country: obj.country,
              email: obj.email,
              url: obj.url
            }),
            basicConstraints: {cA: true, pathLenConstraint: 4},
            keyUsage: ['digitalSignature', 'keyCertSign', 'clientAuth'],
            crl: obj.crl || `https://${obj.domain}/${obj.ipid}/crl`,
            ocsp: obj.ocsp || `https://${obj.domain}/${obj.ipid}/ocsp`,
            x5u: cert => `https://${obj.domain}/${obj.ipid}/certificates/${cert.serial}.x5u`,
            matp: obj.matp || `https://${obj.domain}/${obj.ipid}/matp`
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
              url: obj.url || `https://${obj.domain}`,
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
      const crypto = getCrypto()
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
    const crypto = getCrypto()
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
      cert.setAuthorityInfoAccess(subject.ocsp, subject.x5u)
      if (typeof subject.x5u === 'function') {
        subject.x5u = subject.x5u(cert)
      }
      if (subject.matp) {
        cert.setSubjectInfoAccess(subject.matp)
      }
      //TODO: add references to certificate policy statements

      //TODO: add "x5u" 
      //TODO: add "attestations url"

      await cert.sign(this.private, algorithm)
      await cert.updateFingerprint()
      let certificateBuffer = await cert.toSchema(true).toBER(false)
      certificateBuffer = Buffer.from(certificateBuffer).toString('base64')

      return {
        _id: cert.fingerprint,
        mrn: subject.DN.uid || 'root',
        notAfter: cert.notAfter.value,
        pem: `-----BEGIN CERTIFICATE-----\n${certificateBuffer.replace(/(.{64})(?!$)/g, '$1\n')}\n-----END CERTIFICATE-----\n`,
        serial: cert.serial
      }
    } catch (err) {
      console.log(err)
      throw err
    }
  }

  async getCertificateChain (serial) {
    const top = await DB.certificates.findOne({ serial, mrn: new RegExp(`^${this.uid}:.+`)})
    const chain = top ? [top] : []
    let next = top ? top.parent : null
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
    console.debug(`Issued certificate ${cert.serial} to ${subject.DN.uid}`)
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
    if (subject.x5u) {
      entity.x5u = subject.x5u
    }
    if (! Array.isArray(entity.certificates)) {
      entity.certificates = []
    }
    entity.certificates.unshift(cert._id)
    entity.certificateExpires = cert.notAfter
  }

  async responseForOCSPRequest (buffer) {
    const req = new OCSPRequest(buffer, this.uid)
    const reqCerts = new Map(req.serials.map(s => [s, undefined]))
    const foundCerts = await DB.certificates.find({ serial: {$in: [...reqCerts.keys()]} }, { serial: 1, status: 1, _id: 0})
    const statuses = (foundCerts || []).reduce((obj, cert) => {
      obj[cert.serial] = cert.status || 'good'
      return obj
    }, {})
    await this._loadOwnPEM()
    const resp = OCSPResponse.to(req, this, statuses)
    await this._loadPrivateKey()
    return await resp.toDER()
  }

  static async initialize (mir, config) {
    await MCPCertificate.initialize({spid: mir ? mir.uid : config.ipid })
    if (mir) {
      return mir
    }
    
    let root = {
      ipid: config.ipid,
      domain: config.domain,
      country: config.country,
      email: config.admin || `mir-admin@${config.domain}`
    }
    
    mir = Object.assign(
      root,
      {
        email: config.email || `mir@${config.domain}`,
        url: config.url || `https://${config.domain}/${config.ipid}.html`
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
