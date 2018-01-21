// @ts-check
'use strict'

const expect = require('unexpected')
const { createTestServer } = require('./testutils')
const { rsaPrivateKey, rsaPublicKey } = require('./testresources')

const querystring = require('querystring')
const { JwtServiceAuth, JwtUtils, JwtServiceAuthError } = require('./index')

const r2 = require('r2')
const curl = require('url')

let googleKeyFileData = {
  type: 'service_account',
  project_id: 'test-project',
  private_key_id: '76d81ae69ce620a517b140fc73dbae61e88b34bc',
  private_key: rsaPrivateKey,
  client_email: 'buildstatus@nversion-168820.iam.gserviceaccount.com',
  client_id: '123456789123456789123',
  auth_uri: 'https://accounts.google.com/o/oauth2/auth',
  token_uri: 'https://accounts.google.com/o/oauth2/token',
  auth_provider_x509_cert_url: 'https://www.googleapis.com/oauth2/v1/certs',
  client_x509_cert_url:
    'https://www.googleapis.com/robot/v1/metadata/x509/servicename%40test-project.iam.gserviceaccount.com'
}

const pubKeys = {
  'buildstatus@nversion-168820.iam.gserviceaccount.com': {
    '76d81ae69ce620a517b140fc73dbae61e88b34bc@RS256': rsaPublicKey
  },
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
  let [httpServer, listenPromise] = createTestServer((req, res) => {
    try {
      if (req.url === '/oauth2/v4/token') {
        let chunks = []
        req.on('data', chunk => {
          chunks.push(chunk)
        })
        req.on('end', () => {
          let requestData = Buffer.concat(chunks).toString('utf8')
          if (requestData) {
            let token = querystring.unescape(
              requestData.replace(/^.+assertion=([^&]+).*?$/, '$1')
            )
            let body = JwtUtils.decode(token, pubKeys, [
              'https://www.googleapis.com/oauth2/v4/token'
            ])
            if (body.scope !== '') {
              res.statusCode = 200
              res.end(JSON.stringify({ access_token: 'ok', expires_in: 3600 }))
            } else {
              res.statusCode = 400
              res.end(JSON.stringify({ error: 'scopes not set' }))
            }
          } else {
            res.statusCode = 400
            res.end(JSON.stringify({ error: 'not valid' }))
          }
        })
      } else if (req.url === '/installations/1/access_tokens') {
        let token = req.headers['authorization'].replace(/^Bearer (.+)$/, '$1')
        let body = JwtUtils.decode(token, pubKeys, [
          'https://www.googleapis.com/oauth2/v4/token'
        ])
        res.statusCode = 201
        let now = new Date()
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

  describe('JwtServiceAuthError', () => {
    it('innerError should be null', () => {
      let error = new JwtServiceAuthError('')
      expect(error.innerError, 'to be null')
    })
  })

  describe('getGoogleAccessToken', () => {
    it('should succeed with ok token', () => {
      let jwtServiceAuth = new JwtServiceAuth(httpRequestHandlerR2)
      let accessTokenPromise = jwtServiceAuth.getGoogleAccessToken(
        JSON.stringify(googleKeyFileData)
      )
      return expect(
        accessTokenPromise,
        'to be fulfilled with value satisfying',
        {
          accessToken: 'ok',
          expiresIn: 3600
        }
      )
    })
    it('should fail', () => {
      let jwtServiceAuth = new JwtServiceAuth(httpRequestHandlerR2)
      return jwtServiceAuth
        .getGoogleAccessToken(JSON.stringify(googleKeyFileData), 3600, [])
        .then(accessToken => {
          // This should neven happen so return an error to the catch if it does
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
    it('should fail with bad input', () => {
      let jwtServiceAuth = new JwtServiceAuth(httpRequestHandlerR2)
      expect(() => {
        jwtServiceAuth.getGoogleAccessToken('{}')
      }, 'to throw error')
    })
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
