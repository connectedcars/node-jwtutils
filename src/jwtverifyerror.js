// @ts-check
'use strict'

function JwtVerifyError(message, innerError) {
  this.name = 'JwtVerifyError'
  this.message = message
  this.stack = new Error().stack
  this.innerError = innerError || null
}
JwtVerifyError.prototype = Object.create(Error.prototype)
JwtVerifyError.prototype.constructor = JwtVerifyError

module.exports = JwtVerifyError
