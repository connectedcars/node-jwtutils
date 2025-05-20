#!/usr/bin/env node

/* eslint-disable no-console */

import fs from 'fs'

import { jwtUtils } from '../src'

if (process.argv.length < 3) {
  console.error('Usage: jwtencode privatekey')
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

let privateKey: Buffer | null = null
let privateKeyPassword: string | null = null

function processJwts(buffer: string): string {
  return buffer.replace(
    /(?:^|\n)(?:password\s([^\n]+)\n)?\s*({[^}]+})\n\s*({[^}]+})(?:$|\n)/g,
    (_match, password, headerString, bodyString) => {
      const header = JSON.parse(headerString)
      const body = JSON.parse(bodyString)

      if (password !== undefined) {
        privateKeyPassword = password
      }

      if (privateKey === null) {
        privateKey = fs.readFileSync(privateKeyPath)
      }

      console.log(jwtUtils.encode(privateKey, header, body, privateKeyPassword))

      return ''
    }
  )
}
