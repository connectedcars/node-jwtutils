// @ts-check
'use strict'

const expect = require('unexpected')
const { createTestHttpServer } = require('./testutils')
const { rsaPrivateKey, rsaPublicKey } = require('./testresources')

const { JwtServiceAuth, JwtUtils } = require('./index')

const r2 = require('r2')
const curl = require('url')

const pubKeys = {
  '1': {
    'default@RS256': {
      publicKey: rsaPublicKey,
      validators: {
        aud: () => {
          return true
        }
      }
    }
  }
}

describe('JwtServiceAuth', () => {
  let [httpServer, listenPromise] = createTestHttpServer((req, res) => {
    try {
      if (req.url === '/app/installations/1/access_tokens') {
        let token = req.headers['authorization'].replace(/^Bearer (.+)$/, '$1')
        let body = JwtUtils.decode(token, pubKeys, [])
        res.statusCode = 201
        res.end(
          JSON.stringify({
            token: 'v1.1f699f1069f60xxx',
            expires_at: new Date(
              new Date().getTime() + 3600 * 1000
            ).toISOString()
          })
        )
      } else {
        res.statusCode = 404
        res.end()
      }
    } catch (e) {
      res.statusCode = 400
      res.end(JSON.stringify({ error: 'failed validation' }))
    }
  })

  // Setup httpRequestHandler
  let httpRequestHandlerR2 = null
  let baseUrl = null
  before(done => {
    listenPromise.then(result => {
      baseUrl = `http://localhost:${result.port}`
      httpRequestHandlerR2 = (method, url, headers, body) => {
        // Overwrite to point to test server
        let parsedUrl = curl.parse(url)
        url = `${baseUrl}${parsedUrl.path}`
        // Do http request
        let r2Request = r2[method.toLowerCase()](url, {
          headers,
          body
        }).response
        return r2Request.then(httpResponse => {
          return httpResponse.arrayBuffer().then(data => {
            return {
              statusCode: httpResponse.status,
              data: data,
              headers: httpResponse.headers
            }
          })
        })
      }
      console.log(`Listining on ${result.hostname}:${result.port}`)
      done()
    })
  })

  after(() => {
    httpServer.close()
  })

  describe('getGithubAccessToken', () => {
    it('should succeed with ok token', () => {
      let jwtServiceAuth = new JwtServiceAuth(httpRequestHandlerR2)
      let accessTokenPromise = jwtServiceAuth.getGithubAccessToken(
        rsaPrivateKey,
        1,
        1
      )
      return expect(
        accessTokenPromise,
        'to be fulfilled with value satisfying',
        {
          accessToken: 'v1.1f699f1069f60xxx',
          expiresIn: 3600
        }
      )
    })
    it('should fail', () => {
      let jwtServiceAuth = new JwtServiceAuth(httpRequestHandlerR2)
      return jwtServiceAuth
        .getGithubAccessToken(rsaPrivateKey, 0, 1)
        .then(accessToken => {
          return new Error('Got back accessToken when errors was expected')
        })
        .catch(e => {
          try {
            return expect(e, 'to have message', 'response.statusCode not 200')
          } catch (e) {
            return Promise.reject(e)
          }
        })
    })
  })
})
