import { Request, Response } from 'express'
import http from 'http'

import { JwtUtils, PublicKey, RevokedToken } from './index'
import { JwtVerifyError } from './jwtverifyerror'

type Mapper = (
  user: Record<string, unknown>,
  request: Request,
  response: Response
) => Record<string, unknown> | Promise<Record<string, unknown>>

export function JwtAuthMiddleware(
  pubKeys: Record<string, Record<string, string | PublicKey>>,
  revokedTokens: Record<string, RevokedToken>,
  audiences: string[],
  mapper: Mapper | null = null,
  options: Record<string, string | number | string[] | boolean> = {}
): (
  request: Request & { user?: Record<string, unknown> } & { jwtAuthMiddlewareProcessed?: boolean } & {
    headers: http.IncomingHttpHeaders
  },
  response: Response,
  next: (err?: Error | null) => void
) => void {
  mapper = mapper || null
  options = options || {}
  return function (request, response, next) {
    if (request.jwtAuthMiddlewareProcessed || (request.user || {}).authenticated === true) {
      return next() // Skip authentication if we already authenticated
    }
    if (!(request.headers.authorization || '').startsWith('Bearer ')) {
      if (options.allowAnonymous) {
        request.jwtAuthMiddlewareProcessed = true
        return next()
      }
      return next(new JwtVerifyError('Not allowed'))
    }
    if (!request.headers.authorization) {
      return next(new JwtVerifyError('Missing authorization'))
    }
    try {
      const jwt = request.headers.authorization.substring(7)
      const decodedJwtBody = JwtUtils.decode(jwt, pubKeys, audiences)
      if (!decodedJwtBody.sub) {
        return next(new JwtVerifyError(`Missing 'sub' in body`))
      }
      if (revokedTokens[decodedJwtBody.jti]) {
        return next(new JwtVerifyError(`RevokedToken`))
      }

      request.user = {
        audience: decodedJwtBody.aud,
        issuer: decodedJwtBody.iss,
        subject: decodedJwtBody.sub,
        authenticated: true,
        body: decodedJwtBody
      }

      // Handle async
      let result: ReturnType<Mapper> | null = null
      if (typeof mapper === 'function') {
        result = mapper(request.user, request, response)
      }
      if (result && isPromise(result)) {
        const promiseResult = result as Promise<Record<string, unknown>>

        promiseResult
          .then(() => {
            request.jwtAuthMiddlewareProcessed = true
            next()
          })
          .catch((e: Error) => next(e))
      } else {
        request.jwtAuthMiddlewareProcessed = true
        return next()
      }
    } catch (error) {
      if (error instanceof JwtVerifyError) {
        return next(error)
      } else {
        return next(new JwtVerifyError('Unknown error', error as Record<string, unknown>))
      }
    }
  }
}

function isPromise<T>(value: T): boolean {
  return typeof value === 'object' && value !== null && 'then' in value && typeof value.then === 'function'
}
