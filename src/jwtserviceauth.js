// @ts-check
'use strict'

const jwtEncode = require('./jwtencode')
const querystring = require('querystring')

class JwtServiceAuth {
  /**
   * @typedef {Object} httpHandlerResponse
   * @property {number} statusCode
   * @property {Buffer} data
   * @property {Object} headers
   */

  /**
   *
   * @param {{(method:string, url:string, headers:Object, body:string|Buffer): Promise<httpHandlerResponse>}} httpRequestHandler
   */
  constructor(httpRequestHandler) {
    this.httpRequestHandler = httpRequestHandler
  }

  async getGithubAccessToken(
    privateKey,
    appId,
    installationId,
    expires = 600
  ) {}

  async getGoogleAccessToken(
    keyFileData,
    expires = 3600,
    scopes = ['https://www.googleapis.com/auth/userinfo.email']
  ) {
    let keyData = JSON.parse(keyFileData)

    if (keyData.type !== 'service_account') {
      throw new Error('Only supports service account keyFiles')
    }

    // Create JWT auth token
    let unixNow = Math.floor(new Date().getTime() / 1000)
    let jwtHeader = {
      typ: 'JWT',
      alg: 'RS256',
      kid: keyData.private_key_id
    }
    let jwtBody = {
      aud: 'https://www.googleapis.com/oauth2/v4/token',
      iss: keyData.client_email,
      iat: unixNow,
      exp: unixNow + expires,
      scope: scopes.join(' ')
    }
    let jwt = jwtEncode(keyData.private_key, jwtHeader, jwtBody)

    let formParams = {
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: jwt
    }
    let formData = Object.keys(formParams)
      .map(key => `${key}=${querystring.escape(formParams[key])}`)
      .join('&')

    // Fetch access token
    let response = await this.httpRequestHandler(
      'POST',
      `https://www.googleapis.com/oauth2/v4/token`,
      {
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'tlbdk-buildstatus'
      },
      formData
    )

    if (response.statusCode === 200) {
      return JSON.parse(Buffer.from(response.data).toString('utf8'))
    } else {
      throw new Error('response.statusCode not 200')
    }
  }
}

module.exports = JwtServiceAuth
