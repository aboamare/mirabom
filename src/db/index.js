import Loki from './loki.js'
import Ne from './ne.js'

const Collections = [
  { name: 'keys', unique: '_id', clone: true, cloneMethod: 'shallow' },   // '_id' index needed for Loki, Ne/Mongo always have that
  { name: 'certificates', unique: 'serial' },
  { name: 'entities', unique: '_id'}                                      // '_id' index needed for Loki, Ne/Mongo always have that
]

export default function (cb) {
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