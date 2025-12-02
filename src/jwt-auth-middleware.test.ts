import express from 'express'
import http from 'http'

import { jwtUtils } from './'
import * as RequestHandler from './default-http-request-handler'
import type { ExpressNextFunction, ExpressRequest, ExpressResponse } from './express-types'
import { createJwtAuthMiddlewareHandler } from './jwt-auth-middleware'
import { JwtServiceAuthError } from './jwt-service-auth-error'
import { JwtVerifyError } from './jwt-verify-error'
import type { PublicKeys } from './pubkeys-helper'
import { ecPrivateKey, ecPublicKey } from './test/test-resources'
import type { JwtBody, JwtHeader } from './types'

const jwtHeader: JwtHeader = {
  typ: 'JWT',
  alg: 'ES256',
  kid: '1'
}

const unixNow = Math.floor(Date.now() / 1000)

const jwtBody: JwtBody = {
  aud: 'http://localhost/',
  iss: 'http://localhost/oauth/token',
  jti: 'jtiValid',
  iat: unixNow,
  exp: unixNow + 600,
  scope: ['http://stuff', 'http://stuff2'],
  sub: 'subject@domain.tld',
  email: 'test@domain.tld'
}

const pubKeys: PublicKeys = {
  'http://localhost/oauth/token': {
    '1@ES256': ecPublicKey
  },
  'http://localhost/oauth/token/moreexpires': {
    '1@ES256': {
      publicKey: ecPublicKey,
      expiresSkew: 600
    }
  }
}

const revokedTokens = {
  jtiRevoked: {
    jti: 'jtiRevoked',
    revokedAt: new Date('2023-02-03')
  }
}

const audiences = ['http://localhost/']

interface JwtAuthMiddlewareTestServerOptions {
  port: number
  requestTimeout?: number
}

class JwtAuthMiddlewareTestServer {
  private port: number
  private app: express.Express
  private server?: http.Server

  public constructor(options: JwtAuthMiddlewareTestServerOptions) {
    this.port = options.port
    this.app = express()
    this.app.use(express.json())

    this.app.use(
      '/mapped',
      createJwtAuthMiddlewareHandler(pubKeys, revokedTokens, audiences, user => {
        if (user.issuer === 'http://localhost/oauth/token') {
          // Map claims
          user.eMail = (user.body as { email: string }).email
        }
      })
    )

    this.app.use(
      '/async',
      createJwtAuthMiddlewareHandler(pubKeys, revokedTokens, audiences, user => {
        if (user.subject === 'error') {
          return Promise.reject(new JwtVerifyError('Async error'))
        } else {
          return Promise.resolve('test')
        }
      })
    )

    this.app.use(
      '/anonymous',
      createJwtAuthMiddlewareHandler(pubKeys, revokedTokens, audiences, null, {
        allowAnonymous: true
      })
    )

    this.app.use('/', createJwtAuthMiddlewareHandler(pubKeys, revokedTokens, audiences))

    this.app.get('/anonymous', function (_req: ExpressRequest, res: ExpressResponse) {
      res.statusCode = 200
      res.end('Hello anonymous')
    })

    this.app.get('/', function (req: ExpressRequest & { user?: Record<string, unknown> }, res: ExpressResponse) {
      if (req.user) {
        res.end(`Hello ${req.user.subject as string}`)
      }
    })

    this.app.get('/mapped', function (req: ExpressRequest & { user?: Record<string, unknown> }, res: ExpressResponse) {
      if (req.user) {
        res.end(`Hello ${req.user.eMail as string}`)
      }
    })

    this.app.get('/async', function (_req: ExpressRequest, res: ExpressResponse) {
      res.end(`Async response`)
    })

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    this.app.use((err: Error, _req: ExpressRequest, res: ExpressResponse, _next: ExpressNextFunction) => {
      if (err instanceof JwtVerifyError) {
        res.statusCode = 401
        res.end(err.message)
      } else {
        res.statusCode = 500
        res.end('Unknown error')
      }
    })
  }

  public async start(): Promise<void> {
    this.server = this.app.listen(this.port)
  }

  public async stop(): Promise<void> {
    return new Promise<void>((resolve, reject): void => {
      if (!this.server) {
        return resolve()
      }

      this.server.close((err?: Error): void => {
        if (err) {
          return reject(err)
        }

        resolve()
      })
    })
  }

  public getServer(): http.Server {
    if (this.server) {
      return this.server
    }

    throw new Error('Server does not exist')
  }
}

describe('jwt-auth-middleware', () => {
  let server: JwtAuthMiddlewareTestServer

  function getServerAddress() {
    const address = server.getServer().address()

    if (!address || typeof address === 'string') {
      throw new Error('Resolving server port failed')
    }

    return `http://localhost:${address.port}`
  }

  beforeEach(async () => {
    server = new JwtAuthMiddlewareTestServer({ port: 0 })
    await server.start()
  })

  afterEach(async () => {
    if (server) {
      await server.stop()
    }
  })

  it('should return ok', async () => {
    const jwt = jwtUtils.encode(ecPrivateKey, jwtHeader, jwtBody)

    const responsePromise = RequestHandler.defaultHttpRequestHandler('GET', `${getServerAddress()}/`, {
      Authorization: 'Bearer ' + jwt,
      Accept: 'application/json',
      'User-Agent': 'test'
    })

    await expect(responsePromise).resolves.toMatchObject({
      status: 200,
      data: 'Hello subject@domain.tld'
    })
  })

  it('should return ok for anonymous', async () => {
    const responsePromise = await RequestHandler.defaultHttpRequestHandler('GET', `${getServerAddress()}/anonymous`, {
      Accept: 'application/json',
      'User-Agent': 'test'
    })

    expect(responsePromise).toHaveProperty('data', 'Hello anonymous')
    expect(responsePromise).toHaveProperty('status', 200)
  })

  it('should fail for anonymous with invalid token', async () => {
    const customJwtBody: JwtBody = {
      aud: 'http://localhost/',
      jti: 'jtiValid',
      iat: unixNow,
      exp: unixNow + 600,
      scope: ['http://stuff', 'http://stuff2'],
      sub: 'subject@domain.tld',
      email: 'test@domain.tld'
    }

    const jwt = jwtUtils.encode(ecPrivateKey, jwtHeader, customJwtBody)

    await expect(
      RequestHandler.defaultHttpRequestHandler('GET', `${getServerAddress()}/anonymous`, {
        Authorization: 'Bearer ' + jwt,
        Accept: 'application/json',
        'User-Agent': 'test'
      })
    ).rejects.toThrow(new JwtServiceAuthError('Request failed with status code 401'))
  })

  it('should return ok with a new e-mail', async () => {
    const jwt = jwtUtils.encode(ecPrivateKey, jwtHeader, jwtBody)
    const responsePromise = await RequestHandler.defaultHttpRequestHandler('GET', `${getServerAddress()}/mapped`, {
      Authorization: 'Bearer ' + jwt,
      Accept: 'application/json',
      'User-Agent': 'test'
    })

    expect(responsePromise).toHaveProperty('data', 'Hello test@domain.tld')
    expect(responsePromise).toHaveProperty('status', 200)
  })

  it('should fail because of missing sub', async () => {
    const customJwtBody: JwtBody = {
      aud: 'http://localhost/',
      iss: 'http://localhost/oauth/token',
      jti: 'jtiValid',
      iat: unixNow,
      exp: unixNow + 600,
      scope: ['http://stuff', 'http://stuff2'],
      email: 'test@domain.tld'
    }

    const jwt = jwtUtils.encode(ecPrivateKey, jwtHeader, customJwtBody)

    await expect(
      RequestHandler.defaultHttpRequestHandler('GET', `${getServerAddress()}/`, {
        Authorization: 'Bearer ' + jwt,
        Accept: 'application/json',
        'User-Agent': 'test'
      })
    ).rejects.toThrow(new JwtServiceAuthError('Request failed with status code 401'))
  })

  it('should fail because of revoked token', async () => {
    const customJwtBody = Object.assign({}, jwtBody)
    customJwtBody.jti = 'jtiRevoked'
    const jwt = jwtUtils.encode(ecPrivateKey, jwtHeader, customJwtBody)

    await expect(
      RequestHandler.defaultHttpRequestHandler('GET', `${getServerAddress()}/`, {
        Authorization: 'Bearer ' + jwt,
        Accept: 'application/json',
        'User-Agent': 'test'
      })
    ).rejects.toThrow(new JwtServiceAuthError('Request failed with status code 401'))
  })

  it('should fail because of malform JSON', async () => {
    const jwt = jwtUtils.encode(ecPrivateKey, jwtHeader, jwtBody)

    await expect(
      RequestHandler.defaultHttpRequestHandler('GET', `${getServerAddress()}/`, {
        Authorization: 'Bearer ' + jwt.substring(2),
        Accept: 'application/json',
        'User-Agent': 'test'
      })
    ).rejects.toThrow(new JwtServiceAuthError('Request failed with status code 401'))
  })

  it('should fail with unknown pubkey id', async () => {
    const customJwtHeader = Object.assign({}, jwtHeader)
    customJwtHeader.kid = '2'
    const jwt = jwtUtils.encode(ecPrivateKey, customJwtHeader, jwtBody)

    await expect(
      RequestHandler.defaultHttpRequestHandler('GET', `${getServerAddress()}/`, {
        Authorization: 'Bearer ' + jwt,
        Accept: 'application/json',
        'User-Agent': 'test'
      })
    ).rejects.toThrow(new JwtServiceAuthError('Request failed with status code 401'))
  })

  it('should fail with not allowed because it has no token', async () => {
    await expect(
      RequestHandler.defaultHttpRequestHandler('GET', `${getServerAddress()}/`, {
        Accept: 'application/json',
        'User-Agent': 'test'
      })
    ).rejects.toThrow(new JwtServiceAuthError('Request failed with status code 401'))
  })

  it('should fail with async error', async () => {
    const customJwtBody = Object.assign({}, jwtBody)
    customJwtBody.sub = 'error'

    const jwt = jwtUtils.encode(ecPrivateKey, jwtHeader, customJwtBody)

    await expect(
      RequestHandler.defaultHttpRequestHandler('GET', `${getServerAddress()}/async`, {
        Authorization: 'Bearer ' + jwt,
        Accept: 'application/json',
        'User-Agent': 'test',
        'X-Error': 'Async error'
      })
    ).rejects.toThrow(new JwtServiceAuthError('Request failed with status code 401'))
  })

  it('should success with async', async () => {
    const jwt = jwtUtils.encode(ecPrivateKey, jwtHeader, jwtBody)
    const responsePromise = await RequestHandler.defaultHttpRequestHandler('GET', `${getServerAddress()}/async`, {
      Authorization: 'Bearer ' + jwt,
      Accept: 'application/json',
      'User-Agent': 'test'
    })

    expect(responsePromise).toHaveProperty('data', 'Async response')
    expect(responsePromise).toHaveProperty('status', 200)
  })
})
