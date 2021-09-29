const Loki = require('lokijs')

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
    for (let collectionName of ['keys', 'certificates']) {
      let collection = this.getCollection(collectionName)
      if (collection === null) {
        this.addCollection(collectionName)
      }
    }
  }

  getKey(id) {
    return this.getCollection('keys').findOne({id})
  }

  saveKey(id, pem) {
    this.getCollection('keys').insert({id, pem})
  }

  getCertificate(id) {
    return this.getCollection('certificates').findOne(id)
  }
  
  saveCertificate(id, pem) {
    this.getCollection('certificates').insert({id, pem})
  }
}

module.exports = function (cb) {
  const options = {}
  if (typeof cb == 'function') {
    options.onReady = cb
  }
  return new DB('mir.db', options)
}