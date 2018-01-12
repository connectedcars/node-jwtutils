// @ts-check
'use strict'

const express = require('express')
const app = express()
const http = require('http')
const { JwtUtils, JwtAuthMiddleware, JwtVerifyError } = require('./index')
const expect = require('unexpected')

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
  sub: 'subject@domain.tld',
  email: 'test@domain.tld'
}

const pubKeys = {
  'http://localhost/oauth/token': {
    '1@ES256': ecPublicKey
  },
  'http://localhost/oauth/token/moreexpires': {
    '1@ES256': {
      publicKey: ecPublicKey,
      expiresSkew: 600
    }
  }
}

const audiences = ['http://localhost/']

describe('jwtMiddleware', () => {
  let port = 0
  before(done => {
    let server = http.createServer(app).listen(() => {
      port = server.address().port
      app.set('port', port)
      // Register endponts
      app.use(
        '/mapped',
        JwtAuthMiddleware(pubKeys, audiences, user => {
          if (user.issuer === 'http://localhost/oauth/token') {
            // Map claims
            user.eMail = user.body.email
          }
        })
      )
      app.use(
        '/async',
        JwtAuthMiddleware(pubKeys, audiences, user => {
          if (user.subject === 'error') {
            return Promise.reject(new JwtVerifyError('Async error'))
          } else {
            return Promise.resolve('test')
          }
        })
      )
      app.use('/', JwtAuthMiddleware(pubKeys, audiences))
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
      app.get('/mapped', function(req, res) {
        res.send(`Hello ${req.user.eMail}`)
      })
      app.get('/async', function(req, res) {
        res.send(`Async response`)
      })

      done()
    })
  })

  describe('authentication', () => {
    it('should return ok', () => {
      let jwt = JwtUtils.encode(ecPrivateKey, jwtHeader, jwtBody)
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
    it('should return ok with a new e-mail', () => {
      let jwt = JwtUtils.encode(ecPrivateKey, jwtHeader, jwtBody)
      let responsePromise = doRequest('GET', 'localhost', port, '/mapped', {
        Authorization: 'Bearer ' + jwt,
        Accept: 'application/json',
        'User-Agent': 'test'
      })
      return expect(responsePromise, 'to be fulfilled with value satisfying', {
        statusCode: 200,
        data: 'Hello test@domain.tld'
      })
    })
    it('should fail because of missing sub', () => {
      let customJwtBody = Object.assign({}, jwtBody)
      delete customJwtBody.sub
      let jwt = JwtUtils.encode(ecPrivateKey, jwtHeader, customJwtBody)
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
      let jwt = JwtUtils.encode(ecPrivateKey, jwtHeader, jwtBody)
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
      let jwt = JwtUtils.encode(ecPrivateKey, customJwtHeader, jwtBody)
      let responsePromise = doRequest('GET', 'localhost', port, '/', {
        Authorization: 'Bearer ' + jwt,
        Accept: 'application/json',
        'User-Agent': 'test'
      })
      return expect(responsePromise, 'to be fulfilled with value satisfying', {
        statusCode: 401,
        data: `Unknown pubkey id '2' for this issuer`
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
    it('should fail with async error', () => {
      let customJwtBody = Object.assign({}, jwtBody)
      customJwtBody.sub = 'error'
      let jwt = JwtUtils.encode(ecPrivateKey, jwtHeader, customJwtBody)
      let responsePromise = doRequest('GET', 'localhost', port, '/async', {
        Authorization: 'Bearer ' + jwt,
        Accept: 'application/json',
        'User-Agent': 'test',
        'X-Error': 'Async error'
      })
      return expect(responsePromise, 'to be fulfilled with value satisfying', {
        statusCode: 401,
        data: 'Async error'
      })
    })
    it('should success with async', () => {
      let jwt = JwtUtils.encode(ecPrivateKey, jwtHeader, jwtBody)
      let responsePromise = doRequest('GET', 'localhost', port, '/async', {
        Authorization: 'Bearer ' + jwt,
        Accept: 'application/json',
        'User-Agent': 'test'
      })
      return expect(responsePromise, 'to be fulfilled with value satisfying', {
        statusCode: 200,
        data: 'Async response'
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
