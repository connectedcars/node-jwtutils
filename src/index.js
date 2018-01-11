// @ts-check
'use strict'

const jwtEncode = require('./jwtencode')
const jwtDecode = require('./jwtdecode')
const JwtVerifyError = require('./jwtverifyerror')
const JwtAuthMiddleware = require('./jwtauthmiddleware')
const JwtServiceAuth = require('./jwtserviceauth')

module.exports = {
  JwtUtils: {
    encode: jwtEncode,
    decode: jwtDecode
  },
  JwtVerifyError: JwtVerifyError,
  JwtAuthMiddleware: JwtAuthMiddleware,
  JwtServiceAuth,
  // Support old interface
  encode: jwtEncode,
  decode: jwtDecode
}
