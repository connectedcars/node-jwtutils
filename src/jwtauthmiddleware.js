'use strict'

const jwtUtils = require('./index')
const JwtVerifyError = require('./jwtverifyerror')

function jwtAuthMiddleware(pubKeys, audiences) {
  return function(request, response, next) {
    if (!(request.headers.authorization || '').startsWith('Bearer ')) {
      return next(new JwtVerifyError('Not allowed'))
    }
    try {
      let jwt = request.headers.authorization.substring(7)
      let decodedJwtBody = jwtUtils.decode(jwt, pubKeys, audiences)
      if (!decodedJwtBody.sub) {
        return next(new JwtVerifyError(`Missing 'sub' in body`))
      }
      request.user = {
        subject: decodedJwtBody.sub,
        authenticated: true,
        body: decodedJwtBody
      }
      return next()
    } catch (e) {
      if (e instanceof JwtVerifyError) {
        return next(e)
      } else {
        return next(new JwtVerifyError('Unknown error', e))
      }
    }
  }
}

module.exports = jwtAuthMiddleware
