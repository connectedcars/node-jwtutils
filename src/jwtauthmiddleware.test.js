// @ts-check
'use strict'

const expect = require('unexpected')
const { ecPrivateKey, ecPublicKey } = require('./testresources')

const express = require('express')
const app = express()
const http = require('http')
const { JwtUtils, JwtAuthMiddleware, JwtVerifyError } = require('./index')

const jwtHeader = {
  typ: 'JWT',
  alg: 'ES256',
  kid: '1'
}

const unixNow = Math.floor(Date.now() / 1000)

const jwtBody = {
  aud: 'http://localhost/',
  iss: 'http://localhost/oauth/token',
  jti: 'jtiValid',
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

const revokedTokens = {
  jtiRevoked: new Date(),
  test: new Date('2023-02-03')
}

const audiences = ['http://localhost/']

describe('jwtMiddleware', () => {
  let port = 0
  let server
  before(done => {
    server = http.createServer(app).listen(() => {
      port = server.address().port
      app.set('port', port)
      // Register endponts
      app.use(
        '/mapped',
        JwtAuthMiddleware(pubKeys, revokedTokens, audiences, user => {
          if (user.issuer === 'http://localhost/oauth/token') {
            // Map claims
            user.eMail = user.body.email
          }
        })
      )
      app.use(
        '/async',
        JwtAuthMiddleware(
          pubKeys,
          revokedTokens,
          audiences,
          user => {
            if (user.subject === 'error') {
              return Promise.reject(new JwtVerifyError('Async error'))
            } else {
              return Promise.resolve('test')
            }
          },
          null
        )
      )
      app.use(
        '/anonymous',
        JwtAuthMiddleware(pubKeys, revokedTokens, audiences, null, {
          allowAnonymous: true
        })
      )
      app.use('/', JwtAuthMiddleware(pubKeys, revokedTokens, audiences))
      app.use((err, req, res, next) => {
        if (err instanceof JwtVerifyError) {
          res.status(401).send(err.message)
        } else {
          res.status(500).send('Unknown error')
        }
      })
      app.get('/anonymous', function(req, res) {
        res.send(`Hello anonymous`)
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
  after(done => {
    server.close()
    done()
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
    it('should return ok for anonymous', () => {
      let responsePromise = doRequest('GET', 'localhost', port, '/anonymous', {
        Accept: 'application/json',
        'User-Agent': 'test'
      })
      return expect(responsePromise, 'to be fulfilled with value satisfying', {
        statusCode: 200,
        data: 'Hello anonymous'
      })
    })
    it('should fail for anonymous with invalid token', () => {
      let customJwtBody = Object.assign({}, jwtBody)
      delete customJwtBody.sub
      let jwt = JwtUtils.encode(ecPrivateKey, jwtHeader, customJwtBody)
      let responsePromise = doRequest('GET', 'localhost', port, '/anonymous', {
        Authorization: 'Bearer ' + jwt,
        Accept: 'application/json',
        'User-Agent': 'test'
      })
      return expect(responsePromise, 'to be fulfilled with value satisfying', {
        statusCode: 401,
        data: "Missing 'sub' in body"
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
    it('should fail because of revoked token', () => {
      let customJwtBody = Object.assign({}, jwtBody)
      customJwtBody.jti = 'jtiRevoked'
      let jwt = JwtUtils.encode(ecPrivateKey, jwtHeader, customJwtBody)
      let responsePromise = doRequest('GET', 'localhost', port, '/', {
        Authorization: 'Bearer ' + jwt,
        Accept: 'application/json',
        'User-Agent': 'test'
      })
      return expect(responsePromise, 'to be fulfilled with value satisfying', {
        statusCode: 401,
        data: 'RevokedToken'
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
      customJwtHeader.kid = '2'
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
