// @ts-check
'use strict;'

const urlParser = require('url')
const http = require('http')
const https = require('https')

/**
 * @typedef {Object} HttpResponse
 * @property {number} statusCode
 * @property {string} statusMessage
 * @property {Object} headers
 * @property {Buffer} data
 */

/**
 * Make a http request
 * @param {string} method
 * @param {string} url
 * @param {Object} headers
 * @param {Buffer|string} data
 * @param {Object} options
 * @param {boolean} [options.debug]
 * @param {number} [options.maxResponseSize]
 * @param {number} [options.timeout]
 * @param {string} [options.ca]
 * @return {Promise<HttpResponse>}
 */
function httpRequest(method, url, headers = null, data = null, options = {}) {
  const maxResponseSize = options.maxResponseSize || 10 * 1024 * 1024
  const ca = options.ca || null
  const timeout = options.timeout || 60000

  return new Promise((resolve, reject) => {
    let curl = urlParser.parse(url)
    let httpRequester =
      curl.protocol === 'https:' ? https.request : http.request
    let requestOptions = {
      host: curl.hostname,
      port: curl.port,
      path: curl.path,
      method: method,
      auth: curl.auth,
      headers: headers,
      ca: ca
    }

    var request = httpRequester(requestOptions, response => {
      let responseData = []
      let responseDataLength = 0
      response.on('data', chunk => {
        responseDataLength += chunk.length
        if (responseDataLength <= maxResponseSize) {
          responseData.push(chunk)
        } else {
          response.destroy()
          reject(new HttpRequestError('Response too lange'))
        }
      })
      response.on('end', () => {
        resolve({
          statusCode: response.statusCode,
          statusMessage: response.statusMessage,
          headers: response.headers,
          data: Buffer.concat(responseData)
        })
      })
    })
    request.setTimeout(timeout, () => {
      reject(new HttpRequestError('Timeout'))
    })
    request.on('error', e => {
      reject(e)
    })
    if (data !== null) {
      request.write(data)
    }
    request.end()
  })
}

function HttpRequestError(message, statusCode) {
  this.name = 'HttpRequestError'
  this.statusCode = statusCode
  this.message = message
  this.stack = new Error().stack
}
HttpRequestError.prototype = Object.create(Error.prototype)
HttpRequestError.prototype.constructor = HttpRequestError

module.exports = {
  httpRequest,
  HttpRequestError
}
