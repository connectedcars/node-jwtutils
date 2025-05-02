import { spawn } from 'child_process'
import fs from 'fs'

import { jwtUtils } from '../src'
import type { PublicKeys } from '../src/pubkeys-helper'
import type { JwtBody, JwtHeader } from '../src/types'

describe('jwtencode', () => {
  const rsaPublicKey = fs.readFileSync(`${__dirname}/jwtencode.test.pub`)
  const audiences = ['localhost']

  const pubKeys: PublicKeys = {
    'https://jwt.io': {
      '1@RS256': rsaPublicKey
    }
  }

  const jwtHeader: JwtHeader = {
    alg: 'RS256',
    typ: 'JWT',
    kid: '1'
  }

  const exp = Date.now() + 10_000

  const jwtBody: JwtBody = {
    iss: 'https://jwt.io',
    aud: 'localhost',
    sub: 'subject@domain.tld',
    iat: 1504292127,
    nbf: 1504292127,
    exp
  }

  it('should encode a jwt', async () => {
    const pathToExecutable = `${__dirname}/../build/dist/bin/jwtencode.js`

    if (!fs.existsSync(pathToExecutable)) {
      throw new Error('Could not find jwtencode executable, build the project first (npm run build)')
    }

    const jwtEncode = spawn(pathToExecutable, [`${__dirname}/jwtencode.test.key`])
    const tokenStr = JSON.stringify(jwtHeader, undefined, 2) + '\n' + JSON.stringify(jwtBody, undefined, 2) + '\n'

    const encodePromise = new Promise<JwtBody>((resolve, reject) => {
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
          reject(new Error(error))
        }
      })

      // Read token
      const tokenData: any[] = []

      jwtEncode.stdout.on('data', data => {
        tokenData.push(data)
      })

      jwtEncode.stdout.on('end', () => {
        const jwt = Buffer.concat(tokenData).toString('utf8').trim()

        resolve(jwtUtils.decode(jwt, pubKeys, audiences))
      })
    })

    expect(await encodePromise).toEqual(jwtBody)
  }, 10_000)
})
