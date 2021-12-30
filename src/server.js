'use strict'

const Hapi = require('@hapi/hapi')

const organizations = require('./organizations').routes

const server = Hapi.server({
  port: parseInt(process.env['HTTP_PORT'] || '3001'),
  host: 'localhost'
})

server.route(organizations)


exports.initialize = async () => {
  await server.initialize()
  return server 
}

exports.start = async () => {
  await server.start()
  console.log('Server running on %s', server.info.uri)
  return server
}

process.on('unhandledRejection', (err) => {
  console.log(err)
  process.exit(1)
})
