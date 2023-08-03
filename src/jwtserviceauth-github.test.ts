import { AxiosResponse } from 'axios'
import sinon from 'sinon'

import { defaultHttpRequestHandler } from './defaulthttprequesthandler'
import { JwtServiceAuth } from './jwtserviceauth'
import { JwtServiceAuthTestServer } from './jwtserviceauth-test-server'
import { JwtServiceAuthError } from './jwtserviceautherror'
import { rsaPrivateKey } from './testresources'

describe('JwtServiceAuth', () => {
  const server = new JwtServiceAuthTestServer()
  let clock: sinon.SinonFakeTimers

  let httpRequestHandlerR2: (
    method: string,
    url: string,
    headers?: Record<string, string | number>,
    body?: unknown
  ) => Promise<AxiosResponse<any, any>>

  let baseUrl: string
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
      const jwtServiceAuth = new JwtServiceAuth(httpRequestHandlerR2, {
        endpoint: `${baseUrl}/app/installations/1/access_tokens`
      })
      const accessTokenPromise = await jwtServiceAuth.getGithubAccessToken(rsaPrivateKey, 1, 1)
      return expect(accessTokenPromise).toEqual({
        accessToken: 'v1.1f699f1069f60xxx',
        expiresAt: 3600000,
        expiresIn: 3600
      })
    })
    it('should fail', async () => {
      const jwtServiceAuth = new JwtServiceAuth(httpRequestHandlerR2, {
        endpoint: `${baseUrl}/app/installations/2/access_tokens`
      })
      await expect(jwtServiceAuth.getGithubAccessToken(rsaPrivateKey, 0, 1)).rejects.toThrow(
        new JwtServiceAuthError('Request failed with status code 400')
      )
    })
  })
})
