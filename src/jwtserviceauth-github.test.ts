import { rsaPrivateKey, rsaPublicKey } from './testresources'

// import { JwtServiceAuth, } from './index'
import { JwtServiceAuth } from './jwtserviceauth'

import fs from 'fs'
import path from 'path'
import * as tmp from 'tmp'

import { JwtServiceAuthTestServer } from './jwtserviceauth-test-server'

import { defaultHttpRequestHandler } from './defaulthttprequesthandler'
import { JwtServiceAuthError } from './jwtserviceautherror'
import sinon from 'sinon'

const pubKeys = {
  '1': {
    'default@RS256': {
      publicKey: rsaPublicKey,
      validators: {
        aud: () => {
          return true
        }
      }
    }
  }
}

describe('JwtServiceAuth', () => {

  const server = new JwtServiceAuthTestServer()
  let clock: sinon.SinonFakeTimers

  let httpRequestHandlerR2  = null
  let baseUrl = null
  beforeAll(async () => {
    await server.start()
    baseUrl = `http://localhost:${server.listenPort}`
    httpRequestHandlerR2 = defaultHttpRequestHandler

    clock = sinon.useFakeTimers()
  })

  afterEach(async () => {
    server.reset()
    clock.restore()
  })

  afterAll(async () => {
    await server.stop()
    sinon.restore()
  })

  
  describe('getGithubAccessToken', () => {
    it('should succeed with ok token', async () => {
      let jwtServiceAuth = new JwtServiceAuth(httpRequestHandlerR2, {endpoint: `${baseUrl}/app/installations/1/access_tokens`})
      let accessTokenPromise = await jwtServiceAuth.getGithubAccessToken(
        rsaPrivateKey,
        1,
        1
      )
      return expect(
        accessTokenPromise).
        toEqual(
        {
          accessToken: 'v1.1f699f1069f60xxx',
          expiresAt: 3600000,
          expiresIn: 3600
        }
      )
    })
    it('should fail', async () => {
      let jwtServiceAuth = new JwtServiceAuth(httpRequestHandlerR2, {endpoint: `${baseUrl}/app/installations/2/access_tokens`})
      await expect(jwtServiceAuth.getGithubAccessToken(rsaPrivateKey, 0, 1)).rejects.toThrow(new JwtServiceAuthError('Request failed with status code 400'))
    })
  })
})


