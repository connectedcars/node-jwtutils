// @ts-check
'use strict'

const expect = require('unexpected')
const { createTestServer } = require('./testutils')

const { httpRequest, HttpRequestError } = require('./httprequest')

describe('httpRequest', () => {
  let [httpServer, listenPromise] = createTestServer((req, res) => {
    if (req.url === '/timeout') {
      //
    } else if (req.url === '/large_response') {
      res.statusCode = 200
      res.end('x'.repeat(1024))
    } else if (req.url === '/echo') {
      res.statusCode = 200
      req.on('data', data => {
        res.write(data)
      })
      req.on('end', () => {
        res.end()
      })
    } else {
      res.statusCode = 404
      res.end()
    }
  })

  // Setup httpRequestHandler
  let baseUrl = null
  before(done => {
    listenPromise.then(result => {
      baseUrl = `http://localhost:${result.port}`
      console.log(`Listining on ${result.hostname}:${result.port}`)
      done()
    })
  })

  after(() => {
    httpServer.close()
  })

  it('should return 404', () => {
    let response = httpRequest('GET', baseUrl)
    return expect(response, 'to be fulfilled with value satisfying', {
      statusCode: 404
    })
  })
  it('should return too large', () => {
    let response = httpRequest('GET', `${baseUrl}/large_response`, null, null, {
      maxResponseSize: 512
    })
    return expect(
      response,
      'to be rejected with error satisfying',
      new HttpRequestError('Response too lange')
    )
  })
  it('should return POST data', () => {
    let response = httpRequest('POST', `${baseUrl}/echo`, null, 'Hello')
    return expect(response, 'to be fulfilled with value satisfying', {
      statusCode: 200
    })
  })
  it('should timeout', () => {
    let response = httpRequest('GET', `${baseUrl}/timeout`, null, null, {
      timeout: 1
    })
    return expect(
      response,
      'to be rejected with error satisfying',
      new HttpRequestError('Timeout')
    )
  })
  it('should fail', () => {
    let response = httpRequest('GET', `http://127.0.0.1:1/`, null, null, {
      timeout: 1
    })
    return expect(
      response,
      'to be rejected with error satisfying',
      new Error('connect ECONNREFUSED 127.0.0.1:1')
    )
  })
  it('https connected', () => {
    let response = httpRequest('GET', `https://www.google.com/`)
    return expect(response, 'to be fulfilled with value satisfying', {
      statusCode: 302
    })
  })
})
