const Loki = require('./loki')
const Ne = require('./ne')

const Collections = [
  { name: 'keys', unique: 'id', clone: true, cloneMethod: 'shallow' },
  { name: 'certificates', unique: 'id' },
  { name: 'entities', unique: 'UID'}
]

module.exports = function (cb) {
  const options = {
    onReady: async (db) => {
      await Promise.all(Collections.map(coll => db.ensureCollection(coll.name, coll)))
      console.info('collections created')
      if (typeof cb == 'function') {
        cb(db)
      }
    }
  }
  return Ne(options)
}