import { Request, Response } from 'express'
import http from 'http'

import { jwtUtils } from './index'
import { JwtVerifyError } from './jwt-verify-error'
import type { PublicKeys } from './pubkeys-helper'

export interface RevokedToken {
  id?: number | string
  jti: string
  revokedAt: Date
}

export type Mapper = (
  user: Record<string, unknown>,
  request: Request,
  response: Response
) => void | Record<string, unknown> | Promise<string | Record<string, unknown>>

export interface JwtAuthMiddlewareOptions {
  allowAnonymous?: boolean
}

interface JwtAuthMiddlewareHandlerRequest extends Request {
  user?: Record<string, unknown>
  jwtAuthMiddlewareProcessed?: boolean
  headers: http.IncomingHttpHeaders
}

type JwtAuthMiddlewareHandler = (
  request: JwtAuthMiddlewareHandlerRequest,
  response: Response,
  next: (err?: Error | null) => void
) => void

function isPromise<T>(value: T): boolean {
  return typeof value === 'object' && value !== null && 'then' in value && typeof value.then === 'function'
}

export function JwtAuthMiddleware(
  pubKeys: PublicKeys,
  revokedTokens: Record<string, RevokedToken>,
  audiences: string[],
  mapper: Mapper | null = null,
  options: JwtAuthMiddlewareOptions = {}
): JwtAuthMiddlewareHandler {
  return function (request, response, next) {
    if (request.jwtAuthMiddlewareProcessed || request?.user?.authenticated === true) {
      return next() // Skip authentication if we are already authenticated
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
      const decodedJwtBody = jwtUtils.decode(jwt, pubKeys, audiences)

      if (!decodedJwtBody.sub) {
        return next(new JwtVerifyError(`Missing 'sub' in body`))
      }

      if (decodedJwtBody.jti && revokedTokens[decodedJwtBody.jti]) {
        return next(new JwtVerifyError(`RevokedToken`))
      }

      request.user = {
        audience: decodedJwtBody.aud,
        issuer: decodedJwtBody.iss,
        subject: decodedJwtBody.sub,
        authenticated: true,
        body: decodedJwtBody
      }

      let result: ReturnType<Mapper> | null = null

      if (typeof mapper === 'function') {
        result = mapper(request.user, request, response)
      }

      // Handle async
      if (isPromise(result)) {
        const promiseResult = result as Promise<Record<string, unknown>>

        promiseResult
          .then(() => {
            request.jwtAuthMiddlewareProcessed = true
            next()
          })
          .catch(next)
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
