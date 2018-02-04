const defaultHttpRequestHandler = require('./defaulthttprequesthandler')
const jwkUtils = require('./jwkutils')

/**
 * @typedef {Object} httpHandlerResponse
 * @property {number} statusCode
 * @property {string} statusMessage
 * @property {Buffer} data
 * @property {Object} headers
 */

/**
 * @typedef {Object} accessTokenResponse
 * @property {string} accessToken
 * @property {number} expiresIn
 */

class PubkeysHelper {
  /**
   * Set http request handler for all external http calls
   * @param {{(method:string, url:string, headers:Object, body:string|Buffer): Promise<httpHandlerResponse>}} httpRequestHandler
   */
  constructor(httpRequestHandler = defaultHttpRequestHandler) {
    this.httpRequestHandler = httpRequestHandler
  }

  /**
   * Fetch JWK formated public keys from http endpoint
   * @param {*} url
   * @param {*} options
   */
  fetchJwkKeys(url, options = {}) {
    return this.httpRequestHandler('GET', url).then(response => {
      let pubkeysResponse = JSON.parse(
        Buffer.from(response.data).toString('utf8')
      )
      if (!Array.isArray(pubkeysResponse.keys)) {
        throw new Error(
          `Response from ${url} not in expected format: Missing array property keys`
        )
      }
      if (Object.keys(pubkeysResponse.keys).length === 0) {
        throw new Error(`No keys found in response from ${url}`)
      }

      let pubKeys = {}
      for (const key of pubkeysResponse.keys) {
        let publicKeyPem = jwkUtils.jwtToPem(key)
        pubKeys[`${key.kid}@${key.alg}`] = {
          publicKey: publicKeyPem,
          ...options
        }
      }
      return pubKeys
    })
  }
}

module.exports = PubkeysHelper
