// @ts-check
'use strict'

const expect = require('unexpected')
const { JwtServiceAuth } = require('./index')
const r2 = require('r2')
const http = require('http')

const googleKeyFileDataRsaPublicKey =
  '-----BEGIN PUBLIC KEY-----\n' +
  'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDdlatRjRjogo3WojgGHFHYLugd\n' +
  'UWAY9iR3fy4arWNA1KoS8kVw33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQs\n' +
  'HUfQrSDv+MuSUMAe8jzKE4qW+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1/xAK5D\n' +
  'o2kQ+X5xK9cipRgEKwIDAQAB\n' +
  '-----END PUBLIC KEY-----'

let googleKeyFileData = {
  type: 'service_account',
  project_id: 'test-project',
  private_key_id: '76d81ae69ce620a517b140fc73dbae61e88b34bc',
  private_key:
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
    '-----END RSA PRIVATE KEY-----',
  client_email: 'buildstatus@nversion-168820.iam.gserviceaccount.com',
  client_id: '123456789123456789123',
  auth_uri: 'https://accounts.google.com/o/oauth2/auth',
  token_uri: 'https://accounts.google.com/o/oauth2/token',
  auth_provider_x509_cert_url: 'https://www.googleapis.com/oauth2/v1/certs',
  client_x509_cert_url:
    'https://www.googleapis.com/robot/v1/metadata/x509/servicename%40test-project.iam.gserviceaccount.com'
}

describe.only('JwtServiceAuth', () => {
  let [httpServer, listenPromise] = createTestServer((req, res) => {
    if (req.url === '/') {
      res.statusCode = 200
      res.end(JSON.stringify({ access_token: 'ok' }))
    }
    res.statusCode = 404
    res.end()
  })
  let jwtServiceAuth = null

  before(async () => {
    let { hostname, port } = await listenPromise
    console.log(`Listining on ${hostname}:${port}`)

    let httpRequestHandler = async (method, url, headers, body) => {
      url = `http://localhost:${port}`
      let response = await r2[method.toLowerCase()](url, { headers, body })
        .response
      return {
        statusCode: response.status,
        data: await response.arrayBuffer(),
        headers: response.headers
      }
    }
    jwtServiceAuth = new JwtServiceAuth(httpRequestHandler)
  })

  after(() => {
    httpServer.close()
  })

  describe('JwtServiceAuth', () => {
    it('getGoogleAccessToken', async () => {
      let accessToken = await jwtServiceAuth.getGoogleAccessToken(
        JSON.stringify(googleKeyFileData)
      )
      return expect(accessToken, 'to equal', { access_token: 'ok' })
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
