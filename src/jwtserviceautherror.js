// @ts-check
'use strict'

function JwtServiceAuthError(message, innerError) {
  this.name = 'JwtServiceAuthError'
  this.message = message
  this.stack = new Error().stack
  this.innerError = innerError || null
}
JwtServiceAuthError.prototype = Object.create(Error.prototype)
JwtServiceAuthError.prototype.constructor = JwtServiceAuthError

module.exports = JwtServiceAuthError
