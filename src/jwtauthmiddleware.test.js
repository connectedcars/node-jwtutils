const express = require('express')
const app = express()
const http = require('http')
const jwtUtils = require('./index')
const jwtAuthMiddleware = require('./jwtauthmiddleware')
const expect = require('unexpected')
const JwtVerifyError = require('./jwtverifyerror')

const ecPrivateKey =
  '-----BEGIN EC PRIVATE KEY-----\n' +
  'MHQCAQEEIEbBJ5shjRhQjmWZQfBu8t069BolPpmZjg+c2mSqr8BkoAcGBSuBBAAK\n' +
  'oUQDQgAEgYq9+AtlLZMXL2g61gwOG3vPQPeaWQD+3JcRUdcwdZm4duMXQZrwVBSr\n' +
  '5Kunr1NnK+0VCrcoUh09GFr8UTAq3g==\n' +
  '-----END EC PRIVATE KEY-----'

const ecPublicKey =
  '-----BEGIN PUBLIC KEY-----\n' +
  'MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEgYq9+AtlLZMXL2g61gwOG3vPQPeaWQD+\n' +
  '3JcRUdcwdZm4duMXQZrwVBSr5Kunr1NnK+0VCrcoUh09GFr8UTAq3g==\n' +
  '-----END PUBLIC KEY-----\n'

const jwtHeader = {
  typ: 'JWT',
  alg: 'ES256',
  kid: '1'
}

const unixNow = Math.floor(Date.now() / 1000)

const jwtBody = {
  aud: 'http://localhost/',
  iss: 'http://localhost/oauth/token',
  iat: unixNow,
  exp: unixNow + 600,
  scope: ['http://stuff', 'http://stuff2'],
  sub: 'subject@domain.tld'
}

const pubKeys = {
  'http://localhost/oauth/token': {
    '1@ES256': ecPublicKey
  }
}

describe('jwtMiddleware', () => {
  let port = 0
  before(done => {
    let server = http.createServer(app).listen(() => {
      port = server.address().port
      app.set('port', port)
      // Register endponts
      app.use(jwtAuthMiddleware(pubKeys, ['http://localhost/']))
      app.use((err, req, res, next) => {
        if (err instanceof JwtVerifyError) {
          res.status(401).send(err.message)
        } else {
          res.status(500).send('Unknown error')
        }
      })
      app.get('/', function(req, res) {
        res.send(`Hello ${req.user.subject}`)
      })

      done()
    })
  })

  describe('authentication', () => {
    it('should return ok', () => {
      let jwt = jwtUtils.encode(ecPrivateKey, jwtHeader, jwtBody)
      let responsePromise = doRequest('GET', 'localhost', port, '/', {
        Authorization: 'Bearer ' + jwt,
        Accept: 'application/json',
        'User-Agent': 'test'
      })
      return expect(responsePromise, 'to be fulfilled with value satisfying', {
        statusCode: 200,
        data: 'Hello subject@domain.tld'
      })
    })
    it('should fail because of missing sub', () => {
      let customJwtBody = Object.assign({}, jwtBody)
      delete customJwtBody.sub
      let jwt = jwtUtils.encode(ecPrivateKey, jwtHeader, customJwtBody)
      let responsePromise = doRequest('GET', 'localhost', port, '/', {
        Authorization: 'Bearer ' + jwt,
        Accept: 'application/json',
        'User-Agent': 'test'
      })
      return expect(responsePromise, 'to be fulfilled with value satisfying', {
        statusCode: 401,
        data: "Missing 'sub' in body"
      })
    })
    it('should fail because of malform JSON', () => {
      let jwt = jwtUtils.encode(ecPrivateKey, jwtHeader, jwtBody)
      let responsePromise = doRequest('GET', 'localhost', port, '/', {
        Authorization: 'Bearer ' + jwt.substr(2),
        Accept: 'application/json',
        'User-Agent': 'test'
      })
      return expect(responsePromise, 'to be fulfilled with value satisfying', {
        statusCode: 401,
        data: 'Unknown error'
      })
    })
    it('should fail with unknown pubkey id', () => {
      let customJwtHeader = Object.assign({}, jwtHeader)
      customJwtHeader.kid = 2
      let jwt = jwtUtils.encode(ecPrivateKey, customJwtHeader, jwtBody)
      let responsePromise = doRequest('GET', 'localhost', port, '/', {
        Authorization: 'Bearer ' + jwt,
        Accept: 'application/json',
        'User-Agent': 'test'
      })
      return expect(responsePromise, 'to be fulfilled with value satisfying', {
        statusCode: 401,
        data: 'Unknown pubkey id for this issuer'
      })
    })
    it('should fail with not allowed because it has not token', () => {
      let responsePromise = doRequest('GET', 'localhost', port, '/', {
        Accept: 'application/json',
        'User-Agent': 'test'
      })
      return expect(responsePromise, 'to be fulfilled with value satisfying', {
        statusCode: 401,
        data: 'Not allowed'
      })
    })
  })
})

function doRequest(method, host, port, path, headers) {
  return new Promise((resolve, reject) => {
    var options = {
      host: host,
      path: path,
      port: port,
      method: method,
      headers: headers
    }
    let request = http.request(options, response => {
      var responseData = ''
      response.on('data', chunk => {
        responseData += chunk
      })
      response.on('end', () => {
        resolve({
          statusCode: response.statusCode,
          statusMessage: response.statusMessage,
          headers: response.headers,
          data: responseData
        })
      })
    })
    request.on('error', e => {
      reject(e)
    })
    request.end()
  })
}
