const Boom = require('@hapi/boom')
const jose = require('jose')
const uuid = require('uuid').v4

const { MirError } = require('./errors')

const DB = require('./db')(async db => {
  await Organization.initialize()
})
const { CertificateAuthority } = require('./ca')

const Config = {
  ipid: 'aboamare',
  country: 'FI',
  domain: 'mir.aboamare.net'
}

function isMRN (urn) {
  const re = /^urn:mrn(:[-_a-z0-9.]+)+$/
  return re.test(urn)
}

function MRN (id) {
  return isMRN(id) ? id : `urn:mrn:mcp:id:${Config.ipid}${id ? `:${id}` :''}`
}

class Entity extends Object {
  constructor (props) {
    super()
    if (props._id) {
      props.UID = props._id
      delete props._id
    }
    Object.assign(this, props)
  }

  async save () {
    const dbObj = Object.assign({}, this, {_id: this._id})
    const dontSave = ['UID', 'public', 'private']
    dontSave.forEach(prop => {
      if (dbObj[prop] !== undefined) {
        delete dbObj[prop]
      }
    })
    await DB.entities.upsert(dbObj)
  }

  get _id () {
    return this.UID
  }

  get mrn () {
    return MRN(this.id)
  }

  get x5u () {
    if (this.mir && Array.isArray(this.certificates) && this.certificates.length > 0) {
      return `https://${Config.domain}/${this.mir}/certificates/${this.certificates[0]}.x5u`
    }
    return undefined
  }
}

class Organization extends Entity {

  constructor (props) {
    super(props)

    this.type = 'organization'

    if (this.email && !this.owners) {
      this.owners = [this.email]
    }

  }

  get mir() {
    return super.mir || this.ipid
  }

  mrnFor (id) {
    return isMRN(id) ? id : `${this.mrn}:${id}`
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
        const mir = new CertificateAuthority(this)
        const org = new Organization(Object.assign(
          entity.organization ? this._asTemplate() : this._asOrganizationalUnit(entity), 
          entity, 
          { 
            ipid,
            UID: this.mrnFor(ipid)
          }
        ))
        await mir.issueCertificate(org, 'mir')
        await org.save()
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
    const supportedProps = ['callSign', 'country', 'domain', 'email', 'flagState', 'homePort', 'IMONumber', 'MMSI', 'name', 'organization', 'secondaryMRN', 'unit', 'URL']
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
      subject.public = await jose.exportJWK(key)

      //TODO: support requests for a new cert

      for (const id of this.suggestId(subject)) {
        // try to use a nice memorable id for the subject
        const UID = this.mrnFor(id)
        const existing = await DB.entities.findOne({ _id: UID })
        if (!existing) {
          // now create the certificate
          const mir = new CertificateAuthority(this)
          const entity = new Entity(Object.assign(
            this._asTemplate(['email']), 
            subject,
            { 
              UID,
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
    Object.assign(Config, config)
    let mir = await this.get(Config.ipid)
    if (!mir) {
      mir = new Organization(await CertificateAuthority.initialize(Config))
      await mir.save()
    }
  }
}

const routes = [
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
     * Return a text document with the certificate chain, starting with the cert that has the given fingerprint.
     *
     * The response contains the certificates in PEM format.
     */
    path: '/{ipid}/certificates/{fingerprint}.x5u',
    method: 'GET',
    handler: async function (req, h) {
      const ip = await Organization.get(req.params.ipid)
      if (!ip) {
        throw Boom.notFound()
      }
      try {
        const mir = new CertificateAuthority(ip)
        const chain = await mir.getCertificateChain(req.params.fingerprint)
        if (Array.isArray(chain) && chain.length > 0) {
          return h.response(chain.map(cert => cert.pem).join(''))
            .type('text/plain')
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
      const ip = await Organization.get(req.params.ipid)
      if (!ip) {
        throw Boom.notFound()
      }
      try {
        const mir = new CertificateAuthority(ip)

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
  }
]


module.exports = {
  Organization,
  routes 
}