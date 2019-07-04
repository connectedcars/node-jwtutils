class JwtVerifyError extends Error {
  constructor(message, innerError = null) {
    super(message)
    this.innerError = innerError
  }
}

module.exports = JwtVerifyError
