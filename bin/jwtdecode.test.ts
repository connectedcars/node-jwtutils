import { spawn } from 'child_process'
import { readFileSync } from 'fs'
import sinon from 'sinon'

import { JwtUtils } from '../src/index'

const rsaPrivateKey = readFileSync(`${__dirname}/jwtencode.test.key`).toString()

const jwtHeader = {
  alg: 'RS256',
  typ: 'JWT',
  kid: '1'
}

const jwtBody = {
  iss: 'https://jwt.io',
  aud: 'localhost',
  sub: 'subject@domain.tld',
  iat: 1504292127,
  nbf: 1504292127,
  exp: 1598986470
}

describe('jwtencode', () => {
  let clock: sinon.SinonFakeTimers

  beforeAll(async () => {
    clock = sinon.useFakeTimers()
  })

  afterEach(async () => {
    clock.restore()
  })

  afterAll(async () => {
    sinon.restore()
  })
  it('should return ok', function (done) {
    clock.tick(3000)
    const jwtEncode = spawn(`${__dirname}/jwtdecode.js`, [
      `${__dirname}/jwtencode.test.pub`,
      '1',
      'RS256',
      'https://jwt.io',
      'localhost'
    ])

    const jwt = JwtUtils.encode(rsaPrivateKey, jwtHeader, jwtBody)

    // Write JSON
    jwtEncode.stdin.write(jwt)
    jwtEncode.stdin.end()

    // Read stderr
    let stderrStr = ''
    const errorData: any[] = []
    jwtEncode.stderr.on('data', data => {
      errorData.push(data)
    })
    jwtEncode.stderr.on('end', () => {
      stderrStr = Buffer.concat(errorData).toString('utf8')
    })

    // Read token
    let stdoutStr = ''
    const decodedData: Buffer[] = []
    let error: any
    jwtEncode.stdout.on('data', data => {
      decodedData.push(data)
    })
    jwtEncode.stdout.on('end', () => {
      try {
        stdoutStr = Buffer.concat(decodedData).toString('utf8').trim()
        const decodedBody = JSON.parse(stdoutStr)
        expect(decodedBody).toEqual(jwtBody)
      } catch (e) {
        error = e
      }
    })

    jwtEncode.on('exit', (code, signal) => {
      if (error) {
        // eslint-disable-next-line no-console
        console.log(`stdout:${stdoutStr}\nstderr:${stderrStr}\nexit:${code}`)
        done(error)
      } else {
        done()
      }
    })
  })
})
