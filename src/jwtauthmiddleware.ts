import { JwtUtils } from './index'
import { JwtVerifyError } from './jwtverifyerror'

export interface RevokedToken {
  id?: number | string
  jti: string
  revokedAt: Date
}

//todo: grace make this callable in a better way ie import JwtAuthMiddleware from file
export function JwtAuthMiddleware(
  pubKeys: Record<string, Record<string, unknown>>,
  revokedTokens: Record<string, RevokedToken>,
  audiences: string[],
  mapper = null,
  options: Record<string, unknown> = {}
): (request: any, response: any, next: (error?: Error) => void) => void {
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
          .catch(e => next(e))
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
