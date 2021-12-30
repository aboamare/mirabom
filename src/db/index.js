const Loki = require('./loki')

const Collections = [
  { name: 'keys', unique: 'id', clone: true, cloneMethod: 'shallow' },
  { name: 'certificates', unique: 'id' },
  { name: 'entities', unique: 'UID'}
]

module.exports = function (cb) {
  const options = {
    onReady: async (db) => {
      await Promise.all(Collections.map(coll => db.ensureCollection(coll)))
      console.log('collections created')
      if (typeof cb == 'function') {
        cb(db)
      }
    }
  }
  return Loki(options)
}