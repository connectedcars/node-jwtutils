import { spawn } from 'child_process'
import { readFileSync } from 'fs'
import sinon from 'sinon'

import { JwtUtils } from '../src/index'
import { PublicKey } from '../src/pubkeyshelper'

const rsaPublicKey = readFileSync(`${__dirname}/jwtencode.test.pub`)

const pubKeys: Record<string, Record<string, string | PublicKey>> = {
  'https://jwt.io': {
    '1@RS256': rsaPublicKey.toString()
  }
}

const audiences = ['localhost']

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

    const jwtEncode = spawn(`${__dirname}/jwtencode.js`, [`${__dirname}/jwtencode.test.key`])

    const header = {
      alg: 'RS256',
      typ: 'JWT',
      kid: '1'
    }

    const body = {
      iss: 'https://jwt.io',
      aud: 'localhost',
      sub: 'subject@domain.tld',
      iat: 1504292127,
      nbf: 1504292127,
      exp: 1598986470
    }

    const tokenStr = JSON.stringify(header, null, 2) + '\n' + JSON.stringify(body, null, 2) + '\n'

    // Write JSON
    jwtEncode.stdin.write(tokenStr)
    jwtEncode.stdin.end()

    const errorData: any[] = []
    jwtEncode.stderr.on('data', data => {
      errorData.push(data)
    })
    jwtEncode.stderr.on('data', () => {
      const error = Buffer.concat(errorData).toString('utf8')
      if (error != '') {
        done(new Error(error))
      }
    })

    // Read token
    const tokenData: any[] = []
    jwtEncode.stdout.on('data', data => {
      tokenData.push(data)
    })
    jwtEncode.stdout.on('end', () => {
      const jwt = Buffer.concat(tokenData).toString('utf8').trim()
      const decodedBody = JwtUtils.decode(jwt, pubKeys, audiences)
      expect(body).toEqual(decodedBody)
      done()
    })
  })
})
