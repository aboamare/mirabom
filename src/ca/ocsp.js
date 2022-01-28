import crypto from 'crypto'
import asn1 from 'asn1js'
import pki from 'pkijs'

import { MCPCertificate } from'./certificate.js'

const hashAlgorithms = {
  '1.3.14.3.2.26': 'sha1',
  '2.16.840.1.101.3.4.2.1': 'sha256'
}

const extensions = [
  ['1.3.6.1.5.5.7.48.1.2', 'nonce']
]

const ExtensionIDs = extensions.reduce((map, [id, name]) => {
  map.set(id, name)
  map.set(name, id)
  return map
}, new Map())

export class OCSPRequest extends pki.OCSPRequest {
  constructor (der, issuerUid) {
    const asn = asn1.fromBER(der)
    super({ schema: asn.result })

    this.serials = []
    
    const issuerDnDER = issuerUid ? MCPCertificate.nameAsDER(issuerUid) : undefined
    const nameHashes = {}

    this.certIds.forEach(certId => {
      try {
        const hashAlgorithm = hashAlgorithms[certId.hashAlgorithm.algorithmId]
        if (hashAlgorithm && !nameHashes[hashAlgorithm]) {
          const hashedDN = crypto.createHash(hashAlgorithm).update(Buffer.from(issuerDnDER)).digest().toString('hex')
          nameHashes[hashAlgorithm] = hashedDN
        }
        const issuerNameHash = Buffer.from(certId.issuerNameHash.valueBlock.valueHex).toString('hex')
        if (issuerNameHash === nameHashes[hashAlgorithm]) {
          const serial = Buffer.from(certId.serialNumber.valueBlock.valueHex).toString('hex')
          this.serials.push(serial)
        }
      } catch (err) {
        console.debug(err)
        // ignore this certId / serial
      }
    })

    this.tbsRequest.requestExtensions.forEach(extn => {
      const extnName = ExtensionIDs.get(extn.extnID)
      if (extnName) {
        this[extnName] = extn.extnValue
      }
    })
  }

  get certIds () {
    return this.tbsRequest.requestList.map(req => req.reqCert)
  }

  get nonce () {
    return this._nonce
  }

  set nonce (octectString) {
    this._nonce = Buffer.from(octectString.valueBlock.valueHex).toString('hex')
    console.log(`OCSP request with nonce ${this._nonce}`)
    return this._nonce
  }

}

export class OCSPResponse extends pki.OCSPResponse {
  constructor (issuer, result = 'success') {
    super()
    this._issuer = issuer

    const cert = MCPCertificate.fromPEM(issuer.pem)

    this.responseStatus.valueBlock.valueDec = OCSPResponse.Status[result]
    this.responseBytes = new pki.ResponseBytes()
    this.responseBytes.responseType = "1.3.6.1.5.5.7.48.1.1"

    const ocspBasicResp = new pki.BasicOCSPResponse()
  
		ocspBasicResp.tbsResponseData.responderID = new MCPCertificate({DN: {uid: this._issuer.uid}}).subject
		ocspBasicResp.tbsResponseData.producedAt = new Date()
    ocspBasicResp.certs = [cert]
    this._basicResp = ocspBasicResp
  }

  set nonce (hexString) {
    const responseData = this._basicResp.tbsResponseData
    if (!responseData.responseExtensions) {
      responseData.responseExtensions = []
    }
    const buf = Buffer.from(hexString, 'hex')
    responseData.responseExtensions.push(new pki.Extension({
      extnID: ExtensionIDs.get('nonce'),
      critical: false,
      extnValue: buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength),
      parsedValue: hexString
    }))
  }

  _addCertStatus (certId, status = 'good') {
    function constructStatus (status = 'good') {
      if (status === 'good') {
        return new asn1.Primitive({
          idBlock: {
            tagClass: 3, // CONTEXT-SPECIFIC
            tagNumber: 0 // [0] "good"
          },
          lenBlockLength: 1 // The length contains one byte 0x00
        })
      } else if (typeof status === 'object' && status.revoked) {
        return new asn1.Constructed({
          idBlock: {
            tagClass: 3, // CONTEXT-SPECIFIC
            tagNumber: 1 // [1] "revoked"
          },
          value: [new asn1.GeneralizedTime({ valueDate: status.revoked })]
        })
      } else {
        return new asn1.Primitive({
          idBlock: {
            tagClass: 3, // CONTEXT-SPECIFIC
            tagNumber: 2 // [2] "unknown"
          },
          lenBlockLength: 1 // The length contains one byte 0x00
        })
      }
    }

    const response = new pki.SingleResponse()
    response.certID.hashAlgorithm.algorithmId = certId.hashAlgorithm.algorithmId
    response.certID.issuerNameHash.valueBlock.valueHex = certId.issuerNameHash.valueBlock.valueHex
    response.certID.issuerKeyHash.valueBlock.valueHex = certId.issuerKeyHash.valueBlock.valueHex
    response.certID.serialNumber.valueBlock.valueHex = certId.serialNumber.valueBlock.valueHex
    response.certStatus = constructStatus(status)
    response.thisUpdate = new Date();
    
    this._basicResp.tbsResponseData.responses.push(response)
  }

  async toDER () {
    await this._basicResp.sign(this._issuer.private, this._issuer.algorithm)
    const encodedOCSPBasicResp = this._basicResp.toSchema().toBER(false)
		this.responseBytes.response = new asn1.OctetString({ valueHex: encodedOCSPBasicResp })
    return Buffer.from(this.toSchema().toBER(false))
  }

  async toPEM () {
    const arrayBuf = await this.toDER()
    const b64 = Buffer.from(arrayBuf).toString('base64')
    return `-----BEGIN OCSP RESPONSE -----\n${b64.replace(/(.{64})(?!$)/g, '$1\n')}\n-----END OCSP RESPONSE-----\n`
  }

  static Status = {
    success: 0
  }

  static to (req, ca, statuses = {}, result = 'success') {
    const resp = new this(ca, result)
    if (req.nonce) {
      //TODO: check for replay ?
      resp.nonce = req.nonce
    }
    req.certIds.forEach(certId => {
      const serial = Buffer.from(certId.serialNumber.valueBlock.valueHex).toString('hex')
      resp._addCertStatus(certId, statuses[serial])
    })
    return resp
  }
}