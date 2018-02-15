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
  it('should return ok', function(done) {
    this.timeout(10000)
    this.slow(3000)
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

    // Read stderr
    let stderrStr = ''
    let errorData = []
    jwtEncode.stderr.on('data', data => {
      errorData.push(data)
    })
    jwtEncode.stderr.on('end', () => {
      stderrStr = Buffer.concat(errorData).toString('utf8')
    })

    // Read token
    let stdoutStr = ''
    let decodedData = []
    let error
    jwtEncode.stdout.on('data', data => {
      decodedData.push(data)
    })
    jwtEncode.stdout.on('end', () => {
      try {
        stdoutStr = Buffer.concat(decodedData)
          .toString('utf8')
          .trim()
        let decodedBody = JSON.parse(stdoutStr)
        expect(decodedBody, 'to equal', jwtBody)
      } catch (e) {
        error = e
      }
    })

    jwtEncode.on('exit', (code, signal) => {
      if (error) {
        console.log(`stdout:${stdoutStr}\nstderr:${stderrStr}\nexit:${code}`)
        done(error)
      } else {
        done()
      }
    })
  })
})
