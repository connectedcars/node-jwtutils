// @ts-check
'use strict'

const querystring = require('querystring')
const jwtEncode = require('./jwtencode')
const JwtServiceAuthError = require('./jwtserviceautherror')
const defaultHttpRequestHandler = require('./defaulthttprequesthandler')

/**
 * @typedef {Object} httpHandlerResponse
 * @property {number} statusCode
 * @property {string} statusMessage
 * @property {Buffer} data
 * @property {Object} headers
 */

/**
 * @typedef {Object} accessTokenResponse
 * @property {string} accessToken
 * @property {number} expiresIn
 */

class JwtServiceAuth {
  /**
   * Set http request handler for all external http calls
   * @param {{(method:string, url:string, headers:Object, body:string|Buffer): Promise<httpHandlerResponse>}} httpRequestHandler
   */
  constructor(httpRequestHandler = defaultHttpRequestHandler) {
    this.httpRequestHandler = httpRequestHandler
  }

  /**
   * Get Github Access Token
   * @param {*} privateKey
   * @param {*} appId
   * @param {*} installationId
   * @param {*} expires
   * @returns {Promise<accessTokenResponse>}
   */
  getGithubAccessToken(privateKey, appId, installationId, expires = 600) {
    // Create JWT auth token
    let unixNow = Math.floor(new Date().getTime() / 1000)
    let jwtHeader = {
      typ: 'JWT',
      alg: 'RS256'
    }
    let jwtBody = {
      iat: unixNow,
      exp: unixNow + expires,
      iss: appId
    }

    let jwt = jwtEncode(privateKey, jwtHeader, jwtBody)

    // Fetch access token for installation
    return this.httpRequestHandler(
      'POST',
      `https://api.github.com/installations/${installationId}/access_tokens`,
      {
        Authorization: 'Bearer ' + jwt,
        Accept: 'application/vnd.github.machine-man-preview+json',
        'User-Agent': 'tlbdk-buildstatus'
      }
    ).then(response => {
      if (response.statusCode === 201) {
        let authResponse = JSON.parse(
          Buffer.from(response.data).toString('utf8')
        )
        let now = new Date().getTime()
        let expiresAt = new Date(authResponse.expires_at).getTime()
        return Promise.resolve({
          accessToken: authResponse.token,
          expiresIn: Math.ceil((expiresAt - now) / 1000)
        })
      } else {
        return Promise.reject(
          new JwtServiceAuthError('response.statusCode not 200', {
            statusCode: response.statusCode,
            data: Buffer.from(response.data).toString('utf8')
          })
        )
      }
    })
  }

  /**
   * Get Google Access Token from service account keyfile
   * @param {*} keyFileData
   * @param {*} expires
   * @param {*} scopes
   * @returns {Promise<accessTokenResponse>}
   */
  getGoogleAccessToken(
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
    return this.httpRequestHandler(
      'POST',
      `https://www.googleapis.com/oauth2/v4/token`,
      {
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'tlbdk-buildstatus'
      },
      formData
    ).then(response => {
      if (response.statusCode === 200) {
        let authResponse = JSON.parse(
          Buffer.from(response.data).toString('utf8')
        )
        return Promise.resolve({
          accessToken: authResponse.access_token,
          expiresIn: authResponse.expires_in
        })
      } else {
        return Promise.reject(
          new JwtServiceAuthError('response.statusCode not 200', {
            statusCode: response.statusCode,
            data: Buffer.from(response.data).toString('utf8')
          })
        )
      }
    })
  }
  /* getGoogleAccessTokenFromGCloudHelper() {
    //gcloud config config-helper --format=json
  } */
}

module.exports = JwtServiceAuth
