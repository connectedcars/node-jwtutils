// @ts-check
'use strict'

const jwtEncode = require('./jwtencode')
const jwtDecode = require('./jwtdecode')
const JwtVerifyError = require('./jwtverifyerror')
const JwtServiceAuthError = require('./jwtserviceautherror')
const JwtAuthMiddleware = require('./jwtauthmiddleware')
const JwtServiceAuth = require('./jwtserviceauth')
const PubkeysHelper = require('./pubkeyshelper')
const JwkUtils = require('./jwkutils')

module.exports = {
  JwtUtils: {
    encode: jwtEncode,
    decode: jwtDecode
  },
  JwkUtils,
  PubkeysHelper,
  JwtAuthMiddleware,
  JwtServiceAuth,
  JwtVerifyError,
  JwtServiceAuthError,
  // Support old interface
  encode: jwtEncode,
  decode: jwtDecode
}
