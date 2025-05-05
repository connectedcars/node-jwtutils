/* eslint-disable no-console */

import { spawn } from 'child_process'
import fs from 'fs'

import { jwtUtils } from '../src'
import type { JwtBody, JwtHeader } from '../src/types'

describe('jwtdecode', () => {
  const rsaPrivateKey = fs.readFileSync(`${__dirname}/jwtencode.test.key`)

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

  it('should decode a jwt', async () => {
    const pathToExecutable = `${__dirname}/../build/dist/bin/jwtdecode.js`

    if (!fs.existsSync(pathToExecutable)) {
      throw new Error('Could not find jwtdecode executable, build the project first')
    }

    const jwtDecode = spawn(pathToExecutable, [
      `${__dirname}/jwtencode.test.pub`,
      '1',
      'RS256',
      'https://jwt.io',
      'localhost'
    ])

    const jwt = jwtUtils.encode(rsaPrivateKey, jwtHeader, jwtBody)

    const decodePromise = new Promise<JwtBody>((resolve, reject) => {
      // Write JWT
      jwtDecode.stdin.write(jwt)
      jwtDecode.stdin.end()

      // Read stderr
      let stderrStr = ''
      const errorData: (Buffer | string)[] = []

      jwtDecode.stderr.on('data', data => {
        errorData.push(data)
      })

      jwtDecode.stderr.on('end', () => {
        const data = typeof errorData[0] === 'string' ? errorData.join('') : Buffer.concat(errorData as Buffer[])
        stderrStr = data.toString('utf8')
      })

      // Read token
      let stdoutStr = ''
      let error: Error
      const decodedData: (Buffer | string)[] = []

      jwtDecode.stdout.on('data', data => {
        decodedData.push(data)
      })

      let decodedBody: JwtBody

      jwtDecode.stdout.on('end', () => {
        try {
          const data =
            typeof decodedData[0] === 'string' ? decodedData.join('') : Buffer.concat(decodedData as Buffer[])

          stdoutStr = data.toString('utf8').trim()
          decodedBody = JSON.parse(stdoutStr) as JwtBody
        } catch (_error) {
          error = _error
        }
      })

      jwtDecode.on('exit', code => {
        if (error) {
          console.log(`stdout:${stdoutStr}\n\nstderr:${stderrStr}\n\nexit code:${code}`)
          reject(error)
        } else {
          resolve(decodedBody)
        }
      })
    })

    expect(await decodePromise).toEqual(jwtBody)
  }, 10_000)
})
