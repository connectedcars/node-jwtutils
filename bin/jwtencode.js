#!/usr/bin/env node

'use strict'

const fs = require('fs')
const { JwtUtils } = require('../src')

if (process.argv.length < 3) {
  console.log('jwtencode privatekey')
  process.exit(255)
}
let privateKeyPath = process.argv[2]

process.stdin.resume()
process.stdin.setEncoding('utf8')

let buffer = ''
process.stdin.on('data', function(chunk) {
  buffer += chunk
  buffer = processJwts(buffer)
})

process.stdin.on('end', function() {
  buffer = processJwts(buffer)
})

var privateKey = null
var privateKeyPassword = null

function processJwts(buffer) {
  return buffer.replace(
    /(?:^|\n)(?:password\s([^\n]+)\n)?\s*({[^}]+})\n\s*({[^}]+})(?:$|\n)/g,
    (match, password, headerString, bodyString) => {
      let header = JSON.parse(headerString)
      let body = JSON.parse(bodyString)
      if (password !== undefined) {
        privateKeyPassword = password
      }
      if (privateKey === null) {
        privateKey = fs.readFileSync(privateKeyPath)
      }
      console.log(JwtUtils.encode(privateKey, header, body, privateKeyPassword))
      return ''
    }
  )
}
