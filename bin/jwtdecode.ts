#!/usr/bin/env node

/* eslint-disable no-console */

import fs from 'fs'

import { jwtUtils, type PublicKeys } from '../src'

if (process.argv.length < 6) {
  console.error('Usage: jwtdecode publickeyfile keyid algo issuer audiences')
  process.exit(255)
}

const publicKeyPath = process.argv[2]
const keyId = process.argv[3]
const algo = process.argv[4]
const issuer = process.argv[5]
const audiences = process.argv[6].split(',')

const publicKey = fs.readFileSync(publicKeyPath)

const pubKeys: PublicKeys = {
  [issuer]: {
    [`${keyId}@${algo}`]: publicKey.toString('utf8')
  }
}

process.stdin.resume()
process.stdin.setEncoding('utf8')

let buffer = ''

process.stdin.on('data', function (chunk) {
  buffer += chunk
  buffer = processJwts(buffer)
})

process.stdin.on('end', function () {
  buffer = processJwts(buffer)
})

function processJwts(buffer: string): string {
  return buffer.replace(/(?:^|\n)\s*?([a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+)\s*?(?:$|\n)/g, (match, jwt) => {
    try {
      console.log(JSON.stringify(jwtUtils.decode(jwt, pubKeys, audiences), null, 2))
    } catch (e) {
      console.error(e.message)
    }
    return ''
  })
}
