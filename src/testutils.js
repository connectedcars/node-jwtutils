// @ts-check
'use strict'

const http = require('http')
const https = require('https')

// Make ts-check happy
const HttpServer = http.Server
const HttpsServer = https.Server

/**
 * @typedef {Object} listenResponse
 * @property {string} hostname
 * @property {number} port
 */

/**
 * Start a test http server
 * @param {*} requestHandler
 * @returns {[HttpServer,Promise<listenResponse>]}
 */
function createTestHttpServer(requestHandler) {
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

/**
 * Start a test http server
 * @param {*} requestHandler
 * @returns {[HttpsServer,Promise<listenResponse>]}
 */
function createTestHttpsServer(options, requestHandler) {
  const httpServer = https.createServer(options, requestHandler)
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
  createTestHttpServer,
  createTestHttpsServer
}
