const webcrypto = require('crypto').webcrypto
const asn1 = require('asn1js')
const pki = require('pkijs')
const oid = require('./mcp-oids')

const crypto = new pki.CryptoEngine({name: "node", crypto: webcrypto, subtle: webcrypto.subtle})
pki.setEngine("node", webcrypto, crypto)

class MCPCertificate extends pki.Certificate {
  constructor (subjectOrPEM) {
    if (typeof subjectOrPEM === 'string') {
      let b64 = subjectOrPEM.replace(/^\s?-----BEGIN CERTIFICATE-----/, '')
      b64 = b64.replace(/-----END CERTIFICATE-----/, '')
      b64 = b64.replace(/\s+/g, '')
      const buf = Buffer.from(b64, 'base64')
      const asn = asn1.fromBER(buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength))
      super({schema: asn.result})  
    } else if (typeof subjectOrPEM === 'object' && subjectOrPEM.DN) {
      super()
      this.version = 2 // the version is 0 indexed. TODO: adjust the version based upon presence of extensions and key identifiers
      this.serialNumber = new asn1.Integer({ value: Date.now() })
      this.extensions = []
      this._setDN(subjectOrPEM.DN)
      this._setSubjectAltNames(subjectOrPEM)  
    } else {
      throw TypeError('MCP Certificate can only created from PEM string or object with a DN property.')
    }
  }

  _addTypesAndValues (typesAndValues, obj) {
    typesAndValues.push(...Object.keys(obj).map(attr => {
      let asn1Type = asn1.Utf8String
      const value = obj[attr]
      if (Number.isInteger(value)) {
        asn1Type = asn1.Integer
      }
      return new pki.AttributeTypeAndValue({type: oid[attr], value: new asn1Type({ value })})
    }))  
  }
  
  setIssuer (obj) {
    this._addTypesAndValues(this.issuer.typesAndValues, obj)
  }
  
  _setDN (obj) {
    this._addTypesAndValues(this.subject.typesAndValues, obj)
  }
  
  _setSubjectAltNames (obj) {
    const SAN = obj.SAN
    if (! (SAN && typeof SAN === 'object' && Object.keys(SAN).length)) {
      return
    }

    const sanProperties = Object.keys(SAN)
  
    function otherName (oid, value) {
      return new asn1.Constructed({
        idBlock: {
          tagClass: 3, // CONTEXT-SPECIFIC
          tagNumber: 0 // [0]
        },
        name: "",
        value: [
          new asn1.ObjectIdentifier({ value: oid }),
          new asn1.Constructed({
            idBlock: {
              tagClass: 3, // CONTEXT-SPECIFIC
              tagNumber: 0 // [0]
            },
            value: [new asn1.Utf8String({ value })]
          })
        ]
      })    
    }
  
    const altNames = new asn1.Sequence({
      value: sanProperties.reduce((names, attr) => {
        const type = oid[attr]
        let values = SAN[attr]
        if (! Array.isArray(values)) {
          values = [values]
        }
        values.forEach(value => {
          names.push(otherName(type, value))
        })
        return names
      }, [])
    })
    
    this.extensions.push(new pki.Extension({
      extnID: "2.5.29.17",
      critical: false,
      extnValue: altNames.toBER(false),
      parsedValue: altNames
    }))
  }
  
  setBasicConstraints (obj) {
    const basicConstr = new pki.BasicConstraints(obj)  
    this.extensions.push(new pki.Extension({
      extnID: "2.5.29.19",
      critical: true,
      extnValue: basicConstr.toSchema().toBER(false),
      parsedValue: basicConstr
  }))}
  
  setKeyUsage (keyUses = ['digitalSignature', 'anyKeyUsage']) {
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
    
    this.extensions.push(new pki.Extension({
        extnID: "2.5.29.15",
        critical: false,
        extnValue: keyUsage.toBER(false),
        parsedValue: keyUsage
      })
    )
  
    const keyPurposes = keyUses.map(usage => oid[usage]).filter(use => !!use)
    if (keyPurposes && keyPurposes.length) {
      const extKeyUsage = new pki.ExtKeyUsage({ keyPurposes })
      this.extensions.push(new pki.Extension({
          extnID: '2.5.29.37',
          critical: false,
          extnValue: extKeyUsage.toSchema().toBER(false),
          parsedValue: extKeyUsage // Parsed value for well-known extensions
        })
      )
    }
  }
  
  async setSubjectKeyIdentifier () {
    const keyBytes = this.subjectPublicKeyInfo.subjectPublicKey.valueBlock.valueHex // ArrayBuffer created by ASN1 conversion of the public key
    const sha1 = await crypto.digest('SHA-1', keyBytes)
    const ski = new asn1.OctetString({valueHex: sha1})
    this.extensions.push(new pki.Extension({
      extnID: oid.subjectKeyIdentifier,
      critical: false,
      extnValue: ski.toBER(false),
      parsedValue: ski
    }))
  }
  
  async setAuthorityKeyIdentifier (issuer) {
    const publicKeyInfo = new pki.PublicKeyInfo({json: issuer.public})
    const keyBytes = publicKeyInfo.subjectPublicKey.valueBlock.valueHex
    const sha1 = await crypto.digest('SHA-1', keyBytes)
    const keyIdentifier = new asn1.OctetString({valueHex: sha1})
    const authorityKeyIdentifier = new pki.AuthorityKeyIdentifier({ keyIdentifier })
    this.extensions.push(new pki.Extension({
      extnID: oid.authorityKeyIdentifier,
      critical: false,
      extnValue: authorityKeyIdentifier.toSchema().toBER(false),
      parsedValue: authorityKeyIdentifier
    }))
  }
  
  setCRLDistributionPoints (urls) {
    const distributionPoints = urls.map(uri => new pki.DistributionPoint({ distributionPoint: [new pki.GeneralName( {type: 6, value: uri} )] }))
    const crlDistributionPoints = new pki.CRLDistributionPoints({ distributionPoints })
  
    this.extensions.push(new pki.Extension({
      extnID: oid.crlDistributionPoints,
      critical: false,
      extnValue: crlDistributionPoints.toSchema().toBER(false),
      parsedValue: crlDistributionPoints
    }))
  }
  
  setInfoAccess(ocspUrl, x5u) {
    const accessDescriptions = []

    if (ocspUrl && new URL(ocspUrl)) {
      accessDescriptions.push(new pki.AccessDescription({
        accessMethod: oid.ocsp,
        accessLocation: new pki.GeneralName({ type: 6, value: ocspUrl})
      }))
    }

    if (x5u) {
      const x5uUrl = typeof x5u === 'function' ? x5u(this) : new URL(x5u).toString()
      accessDescriptions.push(new pki.AccessDescription({
        accessMethod: oid.x5u,
        accessLocation: new pki.GeneralName({ type: 6, value: x5uUrl})
      }))
    }
  
    if (accessDescriptions.length > 0) {

      const infoAccess = new pki.InfoAccess({ accessDescriptions })
    
      this.extensions.push(new pki.Extension({
        extnID: oid.authorityInfoAccess,
        critical: false,
        extnValue: infoAccess.toSchema().toBER(false),
        parsedValue: infoAccess
      }))
    }
  }

  async fingerprint (hashAlgorithm = 'SHA-1') {
    let certificateBuffer = await this.toSchema(true).toBER(false) //TODO: should be DER encoding
    const hashBytes = await crypto.digest(hashAlgorithm, certificateBuffer)
    return Buffer.from(hashBytes).toString('hex')
  }

  get serial () {
    return Buffer.from(this.serialNumber.valueBlock.valueHex).toString('hex')
  }

  static fromPEM (pem) {
    return new this(pem)
  }

  static nameAsDER (uidOrObj) {
    const subject = typeof uidOrObj === 'string' ? {DN: {UID: uidOrObj}} : {DN: uidOrObj}
    const cert = new this(subject)
    return cert.subject.toSchema().toBER()
  }
}

module.exports = { crypto, MCPCertificate }