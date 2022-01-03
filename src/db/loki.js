const Loki = require('lokijs')

function open (name, options = {}) {
  let db
  if (typeof options == 'function') {
    const onReady = options
    options = { onReady }
  }
  const defaults = {
    autoload: true,
    autosave: true,
    autosaveInterval: 4000,
  }
  db = new Loki(name, Object.assign(defaults, options))

  process.on('beforeExit', () => db.close())

  db.ensureCollection = async (name, options = {}) => {
    let collection = db.getCollection(name)
    if (collection === null) {
      collection = db.addCollection(name, options)
    }
    return collection
  }

  Loki.Collection.prototype.upsert = async function (obj) {
    if (obj.$loki) {
      return this.update(obj)
    } else {
      return this.insert(obj)
    }
  }

  return db
}



function proxify (lokiDb) {
  return new Proxy(lokiDb, {
    get: function (target, prop) {
      return target.getCollection(prop) || target[prop]
    }
  })
}

let LokiDB
module.exports = function (options) {
  /*
   * Return a new Proxy on the singleton Loki DB
   */
  let proxDb
  if (!LokiDB) {
    LokiDB = open('tmp/mir.json', {
      autoloadCallback: db => {
        if (typeof options.onReady === 'function') {
          options.onReady(proxDb)
        }
      }})
      proxDb = proxify(LokiDB)
  } else {
    proxDb = proxify(LokiDB)
    if (typeof options.onReady === 'function') {
//      process.nextTick(options.onReady(proxDb))
    }
  }
  return proxDb
}