import { MCPEntity } from 'mirau'
import { getCrypto } from './certificate.js'

import db from'./db/index.js'
const DB = db()

function getAlgorithm (key) {
  const ecAlgs = {
    'P-256': 'ES256',
    'P-384': 'ES384'
  }

  let alg
  if (typeof key.crv === 'string') {
    return ecAlgs[key.crv.toUpperCase()]
  }
  return alg || 'SHA-384'
}

export class Entity extends MCPEntity {
  constructor (props) {
    if (props._id) {
      props.uid = props._id
      delete props._id
    }
    super(props)
  }

  async save () {
    const dontSave = ['uid']
    const dbObj = Object.entries(this).reduce((obj, entry) => {
      const [prop, value] = entry
      if (!(prop.startsWith('_') || dontSave.includes(prop) || obj[prop] !== undefined)) {
        obj[prop] = value
      }
      return obj
    }, {_id: this._id, type: this.constructor.name.toLowerCase()})
    await DB.entities.upsert(dbObj)
  }

  get _id () {
    return this.uid
  }

  async createKey (namedCurve = 'P-384') {
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
      this._private = await crypto.exportKey('jwk', keyPair.privateKey)
      this._public = await crypto.exportKey('jwk', keyPair.publicKey)
      return { _private: this._private, _public: this._public }
    } catch (err) {
      console.error(err)
    }
  }

  async loadKey (fingerprint, importPrivate = true) {
    const crypto = getCrypto()
    if (fingerprint || !this._private) {
      const keyPair = await DB.keys.findOne({_id: fingerprint || this.certificates[0]})
      this._public = keyPair._public
      this._private = keyPair._private
      this._fingerprint = keyPair._id
      this._algorithm = getAlgorithm(keyPair._private)
    }
    if (importPrivate !== false) {
      const _private = this._private
      this._private = await crypto.importKey('jwk', _private, {name: 'ECDSA', namedCurve: _private.crv}, _private.ext, _private.key_ops)
    }
  }

  async loadOwnPEM () {
    const cert = await DB.certificates.findOne({ _id: this.certificates[0] })
    this._pem = cert.pem, 
    this._fingerprint = cert._id
    return this.pem
  }

  get publicKey () {
    return this._public
  }

  get privateKey () {
    return this._private
  }

  set publicKey (key) {
    return this._public = key
  }

  get fingerprint () {
    return this._fingerprint || (Array.isArray(this.certificates) ? this.certificates[0] : undefined)
  }

  get algorithm () {
    return this._algorithm || 'SHA-384'
  }

  get signatureAlgorithm () {
    return this._signatureAlgorithm || this.algorithm
  }

  get pem () {
    return this._pem
  }

  static async get (uid) {
    const props = await DB.entities.findOne({ _id: uid })
    return props ? new this(props) : null
  }

}
