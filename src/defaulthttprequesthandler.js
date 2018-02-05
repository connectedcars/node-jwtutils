const { httpRequest } = require('./httprequest')

/**
 * @typedef {Object} httpHandlerResponse
 * @property {number} statusCode
 * @property {string} statusMessage
 * @property {Buffer} data
 * @property {Object} headers
 */

/**
 * Make a http request
 * @param {string} method
 * @param {string} url
 * @param {Object} headers
 * @param {Buffer|string} body
 * @return {Promise<httpHandlerResponse>}
 */
function defaultHttpRequestHandler(method, url, headers, body) {
  return httpRequest(method, url, headers, body)
}

module.exports = defaultHttpRequestHandler
