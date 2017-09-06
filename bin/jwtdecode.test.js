'use strict'
const { spawn } = require('child_process')
const { readFileSync } = require('fs')

const expect = require('unexpected')

const { JwtUtils } = require('../src/index')

const rsaPrivateKey = readFileSync(`${__dirname}/jwtencode.test.key`)

let jwtHeader = {
  alg: 'RS256',
  typ: 'JWT',
  kid: '1'
}

let jwtBody = {
  iss: 'https://jwt.io',
  aud: 'localhost',
  sub: 'subject@domain.tld',
  iat: 1504292127,
  nbf: 1504292127,
  exp: 1598986470
}

describe('jwtencode', () => {
  it('should return ok', done => {
    let jwtEncode = spawn(`${__dirname}/jwtdecode.js`, [
      `${__dirname}/jwtencode.test.pub`,
      '1',
      'RS256',
      'https://jwt.io',
      'localhost'
    ])

    let jwt = JwtUtils.encode(rsaPrivateKey, jwtHeader, jwtBody)

    // Write JSON
    jwtEncode.stdin.write(jwt)
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
    let decodedData = []
    jwtEncode.stdout.on('data', data => {
      decodedData.push(data)
    })
    jwtEncode.stdout.on('end', () => {
      let decodedBodyStr = Buffer.concat(decodedData).toString('utf8').trim()
      let decodedBody = JSON.parse(decodedBodyStr)
      expect(jwtBody, 'to equal', decodedBody)
      done()
    })
  }).slow(2000)
})
