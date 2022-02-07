import Boom from'@hapi/boom'
import * as jose from 'jose'
import {v4 as uuid} from'uuid'
import { Attestation, fetch, initialize as initMirau, MRN, Options } from 'mirau'

import { Entity } from './entity.js'
import { MirError } from'./errors.js'
import { MaritimeIdentityRegistry } from'./mir.js'

import db from'./db/index.js'
const DB = db(async () => {
  await Organization.initialize()
})


const Config = {
  ipid: 'aboamare',
  country: 'FI',
  domain: 'mir.aboamare.net'
}

class OrganizationOptions extends Options {
  constructor (org) {
    super (org.options)
    this.org = org
  }

  trust (certificate) {
    super.trust(certificate)
    this.org.trust(certificate)
  }

  noLongerTrust (certificate) {
    super.noLongerTrust(certificate)
    this.org.noLongerTrust(certificate)
  }
}

export class Organization extends Entity {

  constructor (props) {
    super(props)

    if (this.email && !this.owners) {
      this.owners = [this.email]
    }

    if (!this.options) {
      this.options = { spid: this.uid, 
        trusted: new Map(), 
        trustOwnSubjects: true,
        trustOwnIssuer: true }
    } else if (Array.isArray(this.options.trusted)) {
      this.options.trusted = new Map(this.options.trusted)
    }
  }

  async save (force = false) {
    if (force || this._shouldSave) {
      this.options.trusted = [...this.options.trusted]
      await super.save()
      this.options.trusted = new Map(this.options.trusted)
    }
  }

  get mir() {
    return super.mir || this.ipid
  }

  mrnFor (id) {
    return MRN.test(id) ? id : `${this.mrn}:${id}`
  }

  suggestId (entity = {}) {
    function clean (str) {
      return str.replaceAll(/[^-a-z0-9]/ig, '-').toLowerCase()
    }

    const suggestions = []
    if (typeof entity.ipid === 'string') {
      suggestions.push(clean(entity.ipid))
    }
    if (typeof entity.name === 'string') {
      suggestions.push(clean(entity.name))
    }
    if (typeof entity.organization === 'string') {
      suggestions.push(clean(entity.organization))
    }
    suggestions.push(uuid())
    return suggestions
  }

  _asTemplate (props = ['country', 'domain', 'email', 'organization']) {
    return props.reduce((template, prop) => {
      if (!!this[prop]) {
        template[prop] = this[prop]
      }
      return template
    }, {})
  }

  _asOrganizationalUnit (subject) {
    const template = this._asTemplate()
    template.organization = this.organization || this.ipid
    template.unit = subject.ipid
    return Object.assign(template, subject)
  }

  asMir () {
    return MaritimeIdentityRegistry.from(this)
  }

  async createOrganization (entity = {}) {
    /*
     * Create a new organization in the name space of this (MIR) organization.
     *
     * The new organization inherits the properties of this organization, unless
     * the given properties override those.
     * 
     * Each organization is given an ipid that is unique in the database, not only within
     * the namespace of this organization. This ipid serves as a path component in URLs, etc.
     * 
     */    
    for (const ipid of this.suggestId(entity)) {
      const existing = await DB.entities.findOne({ipid})
      if (!existing) {
        const mir = this.asMir()
        const org = new Organization(Object.assign(
          entity.organization ? this._asTemplate() : this._asOrganizationalUnit(entity), 
          entity, 
          { 
            ipid,
            uid: this.mrnFor(ipid)
          }
        ))
        await mir.issueCertificate(org, 'mir')
        await org.save(true)
        return org
      }
    }
    throw MirError.IdUnavailable()
  }

  async issueCertificate (jws) {
    /*
     * Issue certificate for the entity in the signed JWS. Returns
     * JSON with the issued MRN and with URLs to download the certificate in various forms.
     * 
     * The JWS must have: 
     * - the public key in JWK form, or a reference to a certificate chain (x5u) in case of renewal 
     * - optional properties for the SAN in the certificate
     * 
     */
    const supportedProps = [...Entity.RecognizedProperties]
    try {
      // verify the JWT, the "certificate request" should have the public key of the entity as JWK in the protected header
      const { payload, key } = await jose.flattenedVerify(jws, (protectedHeader, token) => {
        return jose.importJWK(protectedHeader.jwk, protectedHeader.alg)
      })

      // copy only supported properties in the "certificate request" as the subject for the certificate
      const request = JSON.parse(new TextDecoder().decode(payload))
      const subject = supportedProps.reduce((obj, prop) => {
        if (!!request[prop]) {
          obj[prop] = request[prop]
        }
        return obj
      }, {})
      subject.publicKey = await jose.exportJWK(key)

      //TODO: support requests for a new cert

      for (const id of this.suggestId(subject)) {
        // try to use a nice memorable id for the subject
        const uid = this.mrnFor(id)
        const existing = await DB.entities.findOne({ _id: uid })
        if (!existing) {
          // now create the certificate
          const mir = this.asMir()
          const entity = new Entity(Object.assign(
            this._asTemplate(['email']), 
            subject,
            { 
              uid,
              mir: this.ipid
             }
          ))
          await mir.issueCertificate(entity, 'entity')
          await entity.save()
          return entity
        }
      }
      throw MirError.IdUnavailable()        
    } catch (err) {
      console.debug(JSON.stringify(jws))
      console.warn(err)
      throw err
    }
  }

  get validationOptions () {
    if (!this._options) {
      this._options = new OrganizationOptions(this)
    }
    return this._options
  }

  trust (certificate) {
    const { uid, x5t256 } = certificate
    this.options.trusted.set(x5t256, uid)
    this._shouldSave = true
  }

  noLongerTrust (certificate) {
    try {
      this.options.trusted.delete(certificate.fingerprint)
      this._shouldSave = true
    } catch (err) {
      console.info(err)
    }
  }

  async trusts (uid, x5t256) {
    try {
      const mrn = new MRN(uid)
      let trusted = [...this.options.trusted].find((x5t256, u) => u === uid)
      if (!trusted && this.validationOptions.trustOwnSubjects && mrn.issuedBy(this.uid)) {
        const mir = this.asMir()
        trusted = await mir.findCertificate({mrn: uid}, cert => cert.x5t256 === x5t256)
      }
      return !!trusted  
    } catch (err) {
      console.warn(err)
      return false
    }
  }

  async addAttestor (jwt) {
    try {
      const attn = await Attestation.fromJWT(jwt, this.validationOptions)
      if (attn.subject.uid !== this.uid) {
        throw Error(`Attestation is not about ${this.uid} but about ${attn.subject.uid}`)
      }
      if (attn.mirOk || attn.mirEndorsed) {
        const url = (new URL(attn.issuer.matp)).toString()
        if (this.attestors === undefined) {
          this.attestors = {}
        }
        this.attestors[attn.issuer.uid] = url
        this._shouldSave = true
      } else {
        throw Error(`Attestation is not positive`)
      }
    } catch (err) {
      console.info('Received invalid attestation')
      console.info(err)
    }
  }

  async issueAttestionFor (uid, x5t256) {
    const isTrusted = await this.trusts(uid, x5t256)
    if (isTrusted) {
      await this.loadKey(null, false) // 'false' to keep key in jwk format
      const attn = new Attestation(this, {uid, x5t256})
      return await attn.asJWT()
    }
    return undefined
  }

  static _roles = {
    owner: [ /.+/ ]
  }

  static async get (ipid) {
    const autoCreate = ['test']
    const entity = await DB.entities.findOne({ ipid })
    if (entity && entity.type === 'organization') {
      return new Organization(entity)
    } else if (entity) {
      throw MirError.IdUnavailable()
    }
    if (autoCreate.includes(ipid)) {
      const mir = await this.get(Config.ipid)
      return mir.createOrganization({ ipid })
    }
    return undefined
  }

  static async initialize (config = {}) {
    /*
     * Create the top level organization using properties of the given config.
     *
     * Create a root and CA certificate for that top level organization.
     * Send an email confirmation request to the owner email address.
     */
    await initMirau()
    Object.assign(Config, config)
    let mir = await this.get(Config.ipid)
    if (!mir) {
      mir = await MaritimeIdentityRegistry.initialize(Config)
      mir = new Organization(mir)
      await mir.save(true)
    }

    // rewrite URLs to this installation. This ensures that OCSP, MATP and certificate chain
    // between organizations created in this installation will work.
    const rewrittenBaseUrl = `http://localhost:${process.env['HTTP_PORT'] || '3001'}`
    fetch.addRule(new RegExp(`^http(s){0,1}://${Config.domain}`), rewrittenBaseUrl)
  }
}

export const routes = [
  {
    /*
     * Issue a certificate to the entity that PUTs this request.
     * 
     * Alternatively, the holder of an MCP cert can ask for a new
     * certificate for the same MRN, possibly with minor changes in
     * some of the Subject Alternative Names.
     * 
     * The HTTP agent should be authenticated as an admin for the
     * organization in the path. Either by a valid HTTP session, or
     * by client TLS, or by am Authorization header with a (one-time) Bearer token.
     * 
     * The body of the request should be a JWS structure signed with
     * a key generated by the client:
     * - a JWK representation of the public key used to sign the JWS
     * - uid: the id string to use in the MRN for the entity. 
     *        A full MRN in case the entity has already been issued an MRN.
     * - properties that will be part of the SAN of the cert.
     */ 
    path: '/{ipid}/certificates',
    method: 'PUT',
    handler: async function (req, h) {
      const organization = await Organization.get(req.params.ipid)
      if (!organization) {
        return Boom.notFound()
      }
      try {
        const entity = await organization.issueCertificate(req.payload)
        console.debug(JSON.stringify(entity))
        return {
          MRN: entity.mrn,
          x5u: entity.x5u
        }
      } catch (err) {
        return Boom.badRequest()
      }
    }
  },
  {
    /*
     * Return a text document with the certificate chain, starting with the cert that has the given serial (in hex).
     *
     * The response contains the certificates in PEM format.
     */
    path: '/{ipid}/certificates/{serial}.x5u',
    method: 'GET',
    handler: async function (req, h) {
      const idp = await Organization.get(req.params.ipid)
      if (!idp) {
        throw Boom.notFound()
      }
      try {
        const mir = idp.asMir()
        const chain = await mir.getCertificateChain(req.params.serial)
        if (Array.isArray(chain) && chain.length > 0) {
          return h.response(chain.map(cert => cert.pem).join(''))
            .type('application/pem-certificate-chain')
        }        
        return Boom.notFound()
      } catch (err) {
        console.warn(err)
        return Boom.badRequest()
      }
    }
  },
  {
    /*
     * Return an OCSP response, with the status of the requested certificates
     *
     */
    path: '/{ipid}/ocsp',
    method: 'POST',
    options: {
      payload: {
//        allow: ['application/ocsp-request'],
        output: 'data', // to indicate that the handler wants a buffer with the raw body as payload
        parse: false
      }
    },
    handler: async function (req, h) {
      const idp = await Organization.get(req.params.ipid)
      if (!idp) {
        throw Boom.notFound()
      }
      try {
        const mir = idp.asMir()

        // copy the raw, binary, data into an new ArrayBuffer
        const buf = req.payload
        console.debug(req.payload.toString('hex'))
        const arrayBuf = buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength)

        const ocspResponse = await mir.responseForOCSPRequest(arrayBuf)
        return h.response(ocspResponse).type('application/ocsp-response')
      } catch (err) {
        console.warn(err)
        return Boom.badRequest()
      }
    }
  },
  {
    /*
     * Process a submitted attestation, and add the issuer to the list of attestors.
     */
    path: '/{ipid}/matp',
    method: 'POST',
    handler: async function (req, h) {
      const idp = await Organization.get(req.params.ipid)
      if (!idp) {
        throw Boom.notFound()
      }
      try {
        await idp.addAttestor(req.payload)
        await idp.save()
        return h.response()
      } catch (err) {
        console.warn(err)
        return Boom.badRequest()
      }
    }
  },
  {
    /*
     * Return a list of attestors.
     */
    path: '/{ipid}/matp',
    method: 'GET',
    handler: async function (req, h) {
      const idp = await Organization.get(req.params.ipid)
      if (!idp) {
        throw Boom.notFound()
      }
      try {
        return Object.values(idp.attestors || {})
      } catch (err) {
        console.warn(err)
        return Boom.badRequest()
      }
    }
  },
  {
    /*
     * Return an attestion for the requested MIR.
     */
    path: '/{ipid}/matp/{mrn}',
    method: 'GET',
    handler: async function (req, h) {
      const idp = await Organization.get(req.params.ipid)
      if (!idp) {
        throw Boom.notFound()
      }
      try {
        const token = await idp.issueAttestionFor(req.params.mrn, req.query.x5t256)
        if (token) {
          return h.response(token).type('text/plain')
        } else {
          return Boom.notFound()
        }
      } catch (err) {
        console.warn(err)
        return Boom.badRequest()
      }
    }
  }
]
