const express = require('express')
const app = express()
const http = require('http')
const jwtUtils = require('./index')
const jwtAuthMiddleware = require('./jwtauthmiddleware')
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
      //console.log(`Example app listening on port ${port}`)
      // Register endponts
      app.use(jwtAuthMiddleware(pubKeys, ['http://localhost/']))
      app.use((err, req, res, next) => {
        console.log(err.message)
        res.status(500).send(err.message)
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
