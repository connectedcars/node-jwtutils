// @ts-check
'use strict'

const expect = require('unexpected')
const { localhostCertificate, localhostPrivateKey } = require('./testresources')
const { createTestHttpServer, createTestHttpsServer } = require('./testutils')

const { httpRequest, HttpRequestError } = require('./httprequest')

describe('httpRequest', () => {
  let [httpServer, httpListenPromise] = createTestHttpServer((req, res) => {
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
  let [httpsServer, httpsListenPromise] = createTestHttpsServer(
    { cert: localhostCertificate, key: localhostPrivateKey },
    (req, res) => {
      res.statusCode = 200
      res.end()
    }
  )

  // Setup httpRequestHandler
  let httpBaseUrl = null
  let httpsBaseUrl = null
  before(done => {
    Promise.all([httpListenPromise, httpsListenPromise]).then(results => {
      let httpPort = results[0].port
      let httpsPort = results[1].port
      console.log(`Listining on 127.0.0.1:${httpPort} for http`)
      console.log(`Listining on 127.0.0.1:${httpsPort} for https`)
      httpBaseUrl = `http://localhost:${httpPort}`
      httpsBaseUrl = `https://localhost:${httpsPort}`
      done()
    })
  })

  after(() => {
    httpServer.close()
    httpsServer.close()
  })

  it('should return 404', () => {
    let response = httpRequest('GET', httpBaseUrl)
    return expect(response, 'to be fulfilled with value satisfying', {
      statusCode: 404
    })
  })
  it('should return too large', () => {
    let response = httpRequest(
      'GET',
      `${httpBaseUrl}/large_response`,
      null,
      null,
      {
        maxResponseSize: 512
      }
    )
    return expect(
      response,
      'to be rejected with error satisfying',
      new HttpRequestError('Response too lange')
    )
  })
  it('should return POST data', () => {
    let response = httpRequest('POST', `${httpBaseUrl}/echo`, null, 'Hello')
    return expect(response, 'to be fulfilled with value satisfying', {
      statusCode: 200
    })
  })
  it('should timeout', () => {
    let response = httpRequest('GET', `${httpBaseUrl}/timeout`, null, null, {
      timeout: 1
    })
    return expect(
      response,
      'to be rejected with error satisfying',
      new HttpRequestError('Timeout')
    )
  })
  /* it('should fail', () => { // TODO: Find stable way to emulate this as it does not work on travis ci
    let response = httpRequest('GET', `http://127.0.0.1:1/`, null, null, {
      timeout: 1
    })
    return expect(
      response,
      'to be rejected with error satisfying',
      new Error('connect ECONNREFUSED 127.0.0.1:1')
    )
  }) */
  it('https connected', () => {
    let response = httpRequest('GET', httpsBaseUrl, null, null, {
      ca: localhostCertificate
    })
    return expect(response, 'to be fulfilled with value satisfying', {
      statusCode: 200
    })
  })
})
