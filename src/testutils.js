// @ts-check
'use strict'

const http = require('http')

// Make ts-check happy
const Server = http.Server

/**
 * @typedef {Object} listenResponse
 * @property {string} hostname
 * @property {number} port
 */

/**
 * Start a test http server
 * @param {*} requestHandler
 * @returns {[Server,Promise<listenResponse>]}
 */
function createTestServer(requestHandler) {
  const httpServer = http.createServer(requestHandler)
  return [
    httpServer,
    new Promise((resolve, reject) => {
      httpServer.listen(0, () => {
        resolve({
          hostname: httpServer.address().address,
          port: httpServer.address().port
        })
      })
    })
  ]
}

module.exports = {
  createTestServer
}
