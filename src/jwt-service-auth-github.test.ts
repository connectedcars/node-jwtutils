import sinon from 'sinon'

import * as RequestHandler from './default-http-request-handler'
import { JwtServiceAuth } from './jwt-service-auth'
import { JwtServiceAuthError } from './jwt-service-auth-error'
import { JwtServiceAuthTestServer } from './test/jwt-service-auth/jwt-service-auth-test-server'
import { rsaPrivateKey } from './test/test-resources'

describe('JwtServiceAuth', () => {
  const server = new JwtServiceAuthTestServer()
  let clock: sinon.SinonFakeTimers
  let httpRequestHandler: RequestHandler.HttpRequestHandler
  let baseUrl: string

  beforeAll(async () => {
    await server.start()
    baseUrl = `http://localhost:${server.listenPort}`
    httpRequestHandler = RequestHandler.defaultHttpRequestHandler
    clock = sinon.useFakeTimers()
  })

  afterEach(() => {
    server.reset()
    clock.restore()
  })

  afterAll(async () => {
    await server.stop()
    sinon.restore()
  })

  describe('getGithubAccessToken', () => {
    it('should succeed with ok token', async () => {
      const jwtServiceAuth = new JwtServiceAuth(httpRequestHandler, {
        endpoint: `${baseUrl}/app/installations/1/access_tokens`
      })

      await expect(jwtServiceAuth.getGithubAccessToken(rsaPrivateKey, 1, 1)).resolves.toEqual({
        accessToken: 'v1.1f699f1069f60xxx',
        expiresAt: 3600000,
        expiresIn: 3600
      })
    })

    it('should fail for unknown endpoint', async () => {
      const jwtServiceAuth = new JwtServiceAuth(httpRequestHandler, {
        endpoint: `${baseUrl}/app/installations/2/access_tokens`
      })

      await expect(jwtServiceAuth.getGithubAccessToken(rsaPrivateKey, 0, 1)).rejects.toThrow(
        new JwtServiceAuthError('Request failed with status code 400')
      )
    })
  })
})
