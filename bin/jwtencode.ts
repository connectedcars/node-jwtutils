#!/usr/bin/env node
/* eslint-disable no-console */

import fs from 'fs'

import { JwtUtils } from '../src'

if (process.argv.length < 3) {
  console.log('jwtencode privatekey')
  process.exit(255)
}
const privateKeyPath = process.argv[2]

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

let privateKey: Buffer
let privateKeyPassword: string

function processJwts(buffer: string): string {
  return buffer.replace(
    /(?:^|\n)(?:password\s([^\n]+)\n)?\s*({[^}]+})\n\s*({[^}]+})(?:$|\n)/g,
    (match, password, headerString, bodyString) => {
      const header = JSON.parse(headerString)
      const body = JSON.parse(bodyString)
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
