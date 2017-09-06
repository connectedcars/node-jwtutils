#!/usr/bin/env node

'use strict'

const fs = require('fs')
const { JwtUtils } = require('../src')

if (process.argv.length < 6) {
  console.log('jwtdecode publickeyfile keyid algo issuer audiences')
  process.exit(255)
}
let publicKeyPath = process.argv[2]
let keyId = process.argv[3]
let algo = process.argv[4]
let issuer = process.argv[5]
let audiences = process.argv[6]

let publicKey = fs.readFileSync(publicKeyPath)

let pubKeys = {
  [issuer]: {
    [`${keyId}@${algo}`]: publicKey.toString('utf8')
  }
}

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

function processJwts(buffer) {
  return buffer.replace(
    /(?:^|\n)\s*?([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\s*?(?:$|\n)/g,
    (match, jwt) => {
      try {
        console.log(JSON.stringify(JwtUtils.decode(jwt, pubKeys, audiences)))
      } catch (e) {
        console.error(e)
      }
      return ''
    }
  )
}
