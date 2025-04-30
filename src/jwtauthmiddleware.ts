import { Request, Response } from 'express'
import http from 'http'

import { JwtUtils, PublicKey, RevokedToken } from './index'
import { JwtVerifyError } from './jwtverifyerror'

export function JwtAuthMiddleware(
  pubKeys: Record<string, Record<string, string | PublicKey>>,
  revokedTokens: Record<string, RevokedToken>,
  audiences: string[],
  mapper: unknown | null = null,
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
      let result
      if (typeof mapper === 'function') {
        result = mapper(request.user, request, response)
      }
      if (isPromise(result)) {
        result
          .then(() => {
            request.jwtAuthMiddlewareProcessed = true
            next()
          })
          .catch((e: Error) => next(e))
      } else {
        request.jwtAuthMiddlewareProcessed = true
        return next()
      }
    } catch (e) {
      if (e instanceof JwtVerifyError) {
        return next(e)
      } else {
        return next(new JwtVerifyError('Unknown error', e))
      }
    }
  }
}

function isPromise(value: Promise<unknown>): boolean {
  return typeof value === 'object' && value !== null && typeof value.then === 'function'
}
