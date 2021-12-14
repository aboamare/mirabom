const Loki = require('lokijs')

const Collections = {
  keys: {unique: 'id', clone: true, cloneMethod: 'shallow'},
  certificates: {unique: 'id'},
  requests: {},
  accounts: {unique: 'email'}
}

class DB extends Loki {
  constructor (name, options = {}) {
    let onReady = null
    if (typeof options == 'function') {
      onReady = options
      options = {}
    } else {
      onReady = options.onReady || null
    }
    const defaults = {
      autoload: true,
      autosave: true,
      autosaveInterval: 4000,
      autoloadCallback: () => {
        this.ensureCollections()
        if (onReady) {
          onReady(this)
        }       
      }
    }
    super(name, Object.assign(defaults, options))
  }

  ensureCollections () {
    for (let collectionName of Object.keys(Collections)) {
      let collection = this.getCollection(collectionName)
      if (collection === null) {
        this.addCollection(collectionName, Collections[collectionName])
      }
    }
  }

  getKey(id) {
    return this.getCollection('keys').findOne({id})
  }

  saveKey(jsonKeyPair) {
    this.getCollection('keys').insert(jsonKeyPair)
  }

  getCertificate(id) {
    return this.getCollection('certificates').findOne({id})
  }
  
  saveCertificate(entity) {
    if (entity && entity.id && entity.pem) {
      const cert = Object.assign({}, entity)
      if (cert.private) {
        delete cert.private
      }
      this.getCollection('certificates').insert(cert)
    }
  }

  addCSR(pem, entity) {
    const csrObj = Object.assign({pem}, entity)
    this.getCollection('requests').insert(csrObj)
    return csrObj
  }

  getCSR(lokiKey) {
    this.getCollection('request').get(lokiKey)
  }

  updateCSR(csrObj) {
    this.getCollection('requests').update(csrObj)
  }
}

module.exports = function (cb) {
  const options = {
    autosave: true
  }
  if (typeof cb == 'function') {
    options.onReady = cb
  }
  return new DB('mir.json', options)
}