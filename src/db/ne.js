const fs = require('fs/promises')
const { promisify } = require('util')

const Datastore = require('nedb-2')
const { resolve } = require('path')

class Collection extends Object {
  constructor (options) {
    super()
    this._store = new Datastore(options)
  }

  async ensureIndex (options) {
    return new Promise((resolve, reject) => {
      return this._store.ensureIndex(options, (err) => {
        if (err) {
          reject(err)
        } else {
          resolve()
        }
      })
    })
  }

  async find (query, projection) {
    return new Promise((resolve, reject) => {
      return this._store.findOne(query, projection, (err, docs) => {
        if (err) {
          reject(err)
        } else {
          resolve(docs)
        }
      })
    })
  }
  
  async findOne (query, projection) {
    return new Promise((resolve, reject) => {
      return this._store.findOne(query, projection, (err, doc) => {
        if (err) {
          reject(err)
        } else {
          resolve(doc)
        }
      })
    })
  }

  async insert (doc) {
    return new Promise((resolve, reject) => {
      return this._store.insert(doc, (err, newDoc) => {
        if (err) {
          reject(err)
        } else {
          resolve(newDoc)
        }
      })
    })
  }

  async update (query, update, options) {
    return new Promise((resolve, reject) => {
      return this._store.update(query, update, options, (err, numAffected, affectedDocuments, upsert) => {
        if (err) {
          reject(err)
        } else {
          resolve(affectedDocuments)
        }
      })
    })
  }
  
  upsert (doc) {
    return this.update(doc, {$set: doc}, {upsert: true})  
  }
}

class Database extends Object {
  constructor (options = {}) {
    super()
    this.dirPath = options.dirPath || 'tmp'
  }

  onReady (callback) {
    if (this._ready && typeof callback === 'function') {
      process.nextTick(() => {
        callback(this)
      })
    }
    else if (!this._ready) {
      process.nextTick(async () => {
        const stat = await fs.stat(this.dirPath)
        if (!stat.isDirectory) {
          throw Error(`${this.dirPath} is not a directory that the DB can use`)
        }
        this._ready = true
        this.onReady(callback)
      })    
    }
  }

  ensureCollection (name, options = {}) {
    if (this[name] instanceof Collection) {
      return this[name]
    }

    const promise = new Promise((resolve, reject) => {
      const collectionOptions = Object.assign({
        filename: `${this.dirPath}/${name}`,
        autoload: true,
        onload: (err) => {
          if (err) {
            reject(err)
          } else {
            resolve(this[name])
          }
        }
      }, options)
      this[name] = new Collection(collectionOptions)
    })
    if (options.unique) {
      return promise.then(coll => coll.ensureIndex({fieldName: options.unique, unique: true}))
    } else {
      return promise
    }
  }
}

let DB

module.exports = (options = {}) => {
  if (!DB) {
    DB = new Database(options)
  }
  DB.onReady(options.onReady)
  return DB
}