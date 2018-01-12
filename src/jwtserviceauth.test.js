// @ts-check
'use strict'

const expect = require('unexpected')
const querystring = require('querystring')
const { JwtServiceAuth, JwtUtils, JwtServiceAuthError } = require('./index')

const r2 = require('r2')
const http = require('http')
const curl = require('url')

const rsaPublicKey =
  '-----BEGIN PUBLIC KEY-----\n' +
  'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDdlatRjRjogo3WojgGHFHYLugd\n' +
  'UWAY9iR3fy4arWNA1KoS8kVw33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQs\n' +
  'HUfQrSDv+MuSUMAe8jzKE4qW+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1/xAK5D\n' +
  'o2kQ+X5xK9cipRgEKwIDAQAB\n' +
  '-----END PUBLIC KEY-----'

const rsaPrivateKey =
  '-----BEGIN RSA PRIVATE KEY-----\n' +
  'MIICWwIBAAKBgQDdlatRjRjogo3WojgGHFHYLugdUWAY9iR3fy4arWNA1KoS8kVw\n' +
  '33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQsHUfQrSDv+MuSUMAe8jzKE4qW\n' +
  '+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1/xAK5Do2kQ+X5xK9cipRgEKwIDAQAB\n' +
  'AoGAD+onAtVye4ic7VR7V50DF9bOnwRwNXrARcDhq9LWNRrRGElESYYTQ6EbatXS\n' +
  '3MCyjjX2eMhu/aF5YhXBwkppwxg+EOmXeh+MzL7Zh284OuPbkglAaGhV9bb6/5Cp\n' +
  'uGb1esyPbYW+Ty2PC0GSZfIXkXs76jXAu9TOBvD0ybc2YlkCQQDywg2R/7t3Q2OE\n' +
  '2+yo382CLJdrlSLVROWKwb4tb2PjhY4XAwV8d1vy0RenxTB+K5Mu57uVSTHtrMK0\n' +
  'GAtFr833AkEA6avx20OHo61Yela/4k5kQDtjEf1N0LfI+BcWZtxsS3jDM3i1Hp0K\n' +
  'Su5rsCPb8acJo5RO26gGVrfAsDcIXKC+bQJAZZ2XIpsitLyPpuiMOvBbzPavd4gY\n' +
  '6Z8KWrfYzJoI/Q9FuBo6rKwl4BFoToD7WIUS+hpkagwWiz+6zLoX1dbOZwJACmH5\n' +
  'fSSjAkLRi54PKJ8TFUeOP15h9sQzydI8zJU+upvDEKZsZc/UhT/SySDOxQ4G/523\n' +
  'Y0sz/OZtSWcol/UMgQJALesy++GdvoIDLfJX5GBQpuFgFenRiRDabxrE9MNUZ2aP\n' +
  'FaFp+DyAe+b4nDwuJaW2LURbr8AEZga7oQj0uYxcYw==\n' +
  '-----END RSA PRIVATE KEY-----'

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
  let httpRequestHandler = null
  before(done => {
    listenPromise.then(result => {
      httpRequestHandler = (method, url, headers, body) => {
        // Overwrite to point to test server
        let parsedUrl = curl.parse(url)
        url = `http://localhost:${result.port}${parsedUrl.path}`
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
      let jwtServiceAuth = new JwtServiceAuth(httpRequestHandler)
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
      let jwtServiceAuth = new JwtServiceAuth(httpRequestHandler)
      return jwtServiceAuth
        .getGoogleAccessToken(JSON.stringify(googleKeyFileData), 3600, [])
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
    it('should fail with bad input', () => {
      let jwtServiceAuth = new JwtServiceAuth(httpRequestHandler)
      expect(() => {
        jwtServiceAuth.getGoogleAccessToken('{}')
      }, 'to throw error')
    })
  })
  describe('getGithubAccessToken', () => {
    it('should succeed with ok token', () => {
      let jwtServiceAuth = new JwtServiceAuth(httpRequestHandler)
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
      let jwtServiceAuth = new JwtServiceAuth(httpRequestHandler)
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
