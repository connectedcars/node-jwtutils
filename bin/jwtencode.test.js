'use strict'
const { spawn } = require('child_process')
const { readFileSync } = require('fs')

const expect = require('unexpected')

const { JwtUtils } = require('../src/index')

const rsaPublicKey = readFileSync(`${__dirname}/jwtencode.test.pub`)

const pubKeys = {
  'https://jwt.io': {
    '1@RS256': rsaPublicKey
  }
}

const audiences = ['localhost']

describe('jwtencode', () => {
  it('should return ok', done => {
    let jwtEncode = spawn(`${__dirname}/jwtencode.js`, [
      `${__dirname}/jwtencode.test.key`
    ])

    let header = {
      alg: 'RS256',
      typ: 'JWT',
      kid: '1'
    }

    let body = {
      iss: 'https://jwt.io',
      aud: 'localhost',
      sub: 'subject@domain.tld',
      iat: 1504292127,
      nbf: 1504292127,
      exp: 1598986470
    }

    let tokenStr =
      JSON.stringify(header, null, 2) + '\n' + JSON.stringify(body, 2) + '\n'

    // Write JSON
    jwtEncode.stdin.write(tokenStr)
    jwtEncode.stdin.end()

    let errorData = []
    jwtEncode.stderr.on('data', data => {
      errorData.push(data)
    })
    jwtEncode.stderr.on('data', () => {
      let error = Buffer.concat(errorData).toString('utf8')
      if (error != '') {
        done(new Error(error))
      }
    })

    // Read token
    let tokenData = []
    jwtEncode.stdout.on('data', data => {
      tokenData.push(data)
    })
    jwtEncode.stdout.on('end', () => {
      let jwt = Buffer.concat(tokenData).toString('utf8').trim()
      let decodedBody = JwtUtils.decode(jwt, pubKeys, audiences)
      expect(body, 'to equal', decodedBody)
      done()
    })
  }).slow(2000)
})
