// @ts-check
'use strict'

const jwtDecode = require('./jwtdecode')
const JwtVerifyError = require('./jwtverifyerror')

function jwtAuthMiddleware(pubKeys, audiences, mapper = null) {
  return function(request, response, next) {
    if ((request.user || {}).authenticated === true) {
      return next() // Skip authentication if we already authenticated
    }
    if (!(request.headers.authorization || '').startsWith('Bearer ')) {
      return next(new JwtVerifyError('Not allowed'))
    }
    try {
      let jwt = request.headers.authorization.substring(7)
      let decodedJwtBody = jwtDecode(jwt, pubKeys, audiences)
      if (!decodedJwtBody.sub) {
        return next(new JwtVerifyError(`Missing 'sub' in body`))
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
        result.then(() => next()).catch(e => next(e))
      } else {
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
  if (
    typeof value === 'object' &&
    value !== null &&
    typeof value.then === 'function'
  ) {
    return true
  }
  return false
}

module.exports = jwtAuthMiddleware
