// @ts-check
'use strict'

const jwtDecode = require('./jwtdecode')
const JwtVerifyError = require('./jwtverifyerror')

/**
 *
 * @param {Object} pubKeys
 * @param {Array<string>} audiences
 * @param {Function} [mapper]
 * @param {Object} [options]
 * @param {boolean} [options.allowAnonymous]
 */
function jwtAuthMiddleware(
  pubKeys,
  revokedKeys,
  audiences,
  mapper = null,
  options = {}
) {
  mapper = mapper || null
  options = options || {}
  return function(request, response, next) {
    if (
      request.jwtAuthMiddlewareProcessed ||
      (request.user || {}).authenticated === true
    ) {
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
      let jwt = request.headers.authorization.substring(7)
      let decodedJwtBody = jwtDecode(jwt, pubKeys, audiences)
      if (!decodedJwtBody.sub) {
        return next(new JwtVerifyError(`Missing 'sub' in body`))
      }
      if (revokedKeys.includes(decodedJwtBody.jti)) {
        return next(new JwtVerifyError(`Revoked token`))
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

function isPromise(value) {
  return (
    typeof value === 'object' &&
    value !== null &&
    typeof value.then === 'function'
  )
}

module.exports = jwtAuthMiddleware
