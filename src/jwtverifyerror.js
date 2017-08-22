'use strict'

function JwtVerifyError(message, innerError = null) {
  this.name = 'JwtVerifyError'
  this.message = message
  this.stack = new Error().stack
  this.innerError = innerError
}
JwtVerifyError.prototype = Object.create(Error.prototype)
JwtVerifyError.prototype.constructor = JwtVerifyError

module.exports = JwtVerifyError
