import express, { Request, Response } from 'express'
import http from 'http'

import { PublicKey } from '../../index'
import { JwtAuthMiddleware } from '../../jwt-auth-middleware'
import { JwtVerifyError } from '../../jwt-verify-error'
import { ecPublicKey } from '../test-resources'

const pubKeys: Record<string, Record<string, string | PublicKey>> = {
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

export class JwtAuthMiddlewareTestServer {
  private port: number
  private app: express.Express
  private server?: http.Server

  public constructor(options: JwtAuthMiddlewareTestServerOptions) {
    this.port = options.port
    this.app = express()
    this.app.use(express.json())

    this.app.use(
      '/mapped',
      JwtAuthMiddleware(pubKeys, revokedTokens, audiences, (user: Record<string, unknown>) => {
        if (user.issuer === 'http://localhost/oauth/token') {
          // Map claims
          user.eMail = (user.body as { email: string }).email
        }
      })
    )

    this.app.use(
      '/async',
      JwtAuthMiddleware(pubKeys, revokedTokens, audiences, (user: Record<string, unknown>) => {
        if (user.subject === 'error') {
          return Promise.reject(new JwtVerifyError('Async error'))
        } else {
          return Promise.resolve('test')
        }
      })
    )

    this.app.use(
      '/anonymous',
      JwtAuthMiddleware(pubKeys, revokedTokens, audiences, null, {
        allowAnonymous: true
      })
    )

    this.app.use('/', JwtAuthMiddleware(pubKeys, revokedTokens, audiences))

    this.app.get('/anonymous', function (_req: Request, res: Response) {
      res.send(`Hello anonymous`)
    })

    this.app.get('/', function (req: Request & { user?: Record<string, unknown> }, res: Response) {
      if (req.user) {
        res.send(`Hello ${req.user.subject as string}`)
      }
    })

    this.app.get('/mapped', function (req: Request & { user?: Record<string, unknown> }, res: Response) {
      if (req.user) {
        res.send(`Hello ${req.user.eMail as string}`)
      }
    })

    this.app.get('/async', function (_req: Request, res: Response) {
      res.send(`Async response`)
    })

    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    this.app.use((err: Error, _req: Request, res: Response, _next: (err?: Error | null) => void) => {
      if (err instanceof JwtVerifyError) {
        res.status(401).send(err.message)
      } else {
        // eslint-disable-next-line no-console
        console.log('i am here')
        res.status(500).send('Unknown error')
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
