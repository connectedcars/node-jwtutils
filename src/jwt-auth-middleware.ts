import type { NextFunction, Request, Response } from 'express'
import http from 'http'

import { jwtUtils } from './index'
import { JwtVerifyError } from './jwt-verify-error'
import type { PublicKeys } from './pubkeys-helper'

export interface RevokedToken {
  id?: number | string
  jti: string
  revokedAt: Date
}

export type ResultMapper = (
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

export type JwtAuthMiddlewareHandler = (
  request: JwtAuthMiddlewareHandlerRequest,
  response: Response,
  next: NextFunction
) => void

function isPromise<T>(value: T): boolean {
  return typeof value === 'object' && value !== null && 'then' in value && typeof value.then === 'function'
}

export function createJwtAuthMiddlewareHandler(
  pubKeys: PublicKeys,
  revokedTokens: Record<string, RevokedToken>,
  audiences: string[],
  mapper: ResultMapper | null = null,
  options: JwtAuthMiddlewareOptions = {}
): JwtAuthMiddlewareHandler {
  return function (request, response, next) {
    if (request.jwtAuthMiddlewareProcessed || request?.user?.authenticated === true) {
      return next() // Skip authentication if we are already authenticated
    }

    const authorization = request.headers.authorization || ''

    if (!authorization.startsWith('Bearer ')) {
      if (options.allowAnonymous) {
        request.jwtAuthMiddlewareProcessed = true
        return next()
      }

      return next(new JwtVerifyError('Not allowed'))
    }

    try {
      const jwt = authorization.substring(7)
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

      let result: ReturnType<ResultMapper> | null = null

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
        return next(new JwtVerifyError('Unknown error', error as Error))
      }
    }
  }
}
