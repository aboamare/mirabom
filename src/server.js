'use strict'

import Hapi from '@hapi/hapi'

import {routes as  organizations} from './organizations.js'

const server = Hapi.server({
  port: parseInt(process.env['HTTP_PORT'] || '3001'),
  host: 'localhost'
})

server.route(organizations)


export async function initialize () {
  await server.initialize()
  return server 
}

export async function start () {
  await server.start()
  console.log('Server running on %s', server.info.uri)
  return server
}

process.on('unhandledRejection', (err) => {
  console.log(err)
  process.exit(1)
})
