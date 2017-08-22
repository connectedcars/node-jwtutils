'use strict'

const jwtUtils = require('./index')
const JwtVerifyError = require('./jwtverifyerror')

function jwtAuthMiddleware(pubKeys, audiences) {
  return function(request, response, next) {
    if ((request.headers.authorization || '').startsWith('Bearer ')) {
      let jwt = request.headers.authorization.substring(7)
      try {
        let decodedJwtBody = jwtUtils.decode(jwt, pubKeys, audiences)
        if (decodedJwtBody.sub) {
          request.user = {
            subject: decodedJwtBody.sub,
            authenticated: true,
            body: decodedJwtBody
          }
          return next()
        } else {
          return next(new JwtVerifyError('No sub set on jwt'))
        }
      } catch (e) {
        return next(e)
      }
    } else {
      return next(new JwtVerifyError('Not allowed'))
    }
  }
}

module.exports = jwtAuthMiddleware
