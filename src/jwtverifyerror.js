function JwtVerifyError(message) {
  this.name = 'JwtVerifyError'
  this.message = message
  this.stack = new Error().stack
}
JwtVerifyError.prototype = Object.create(Error.prototype)
JwtVerifyError.prototype.constructor = JwtVerifyError

module.exports = JwtVerifyError
