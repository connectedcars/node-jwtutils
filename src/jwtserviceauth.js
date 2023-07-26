// @ts-check
'use strict'

const querystring = require('querystring')
const jwtEncode = require('./jwtencode')
const JwtServiceAuthError = require('./jwtserviceautherror')
const defaultHttpRequestHandler = require('./defaulthttprequesthandler')
const ProcessUtils = require('./processutils')

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
 * @property {number} expiresAt
 */

class JwtServiceAuth {
  /**
   * Set http request handler for all external http calls
   * @param {object} options
   * @param {string} [options.endpoint=https://www.googleapis.com/oauth2/v4/token]
   */
  constructor(options = {}) {
    this.authEndpoint =
      options.endpoint || 'https://www.googleapis.com/oauth2/v4/token'
  }

  /**
   * Get Github Access Token
   * @param {string} privateKey
   * @param {string} appId
   * @param {string} installationId
   * @param {string} appName
   * @param {Object} [options]
   * @param {number} [options.expires]
   * @returns {Promise<accessTokenResponse>}
   */
  getGithubAccessToken(
    privateKey,
    appId,
    installationId,
    appName,
    options = {}
  ) {
    let expires = options.expires ? options.expires : 600

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
    // return axios.post()
    return this.httpRequestHandler(
      'POST',
      `https://api.github.com/app/installations/${installationId}/access_tokens`,
      {
        Authorization: 'Bearer ' + jwt,
        'User-Agent': appName ? appName : 'jwtutils',
        Accept: 'application/vnd.github.machine-man-preview+json'
      },
      undefined
    ).then(response => {
      if (response.statusCode === 201) {
        let authResponse = JSON.parse(
          Buffer.from(response.data).toString('utf8')
        )
        let now = new Date().getTime()
        let expiresAt = new Date(authResponse.expires_at).getTime()
        return Promise.resolve({
          accessToken: authResponse.token,
          expiresIn: Math.ceil((expiresAt - now) / 1000),
          expiresAt: expiresAt
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
   * @param {string} keyFileData
   * @param {Array<string>} [scopes=['https://www.googleapis.com/auth/userinfo.email']]
   * @param {Object} [options]
   * @param {number} [options.expires=3600]
   * @param {string} [options.impersonate]
   * @returns {Promise<accessTokenResponse>}
   */
  getGoogleAccessToken(keyFileData, scopes = null, options = {}) {
    let mergedConfig = Object.assign({}, options, {
      endpoint: this.authEndpoint
    })
    return _getGoogleAccessToken(
      this.httpRequestHandler,
      keyFileData,
      scopes,
      mergedConfig
    )
  }

  /**
   * Get Google Access Token from service account keyfile
   * @param {string} keyFileData
   * @param {Array<string>} [scopes=['https://www.googleapis.com/auth/userinfo.email']]
   * @param {Object} [options]
   * @param {number} [options.expires=3600]
   * @param {string} [options.impersonate]
   * @param {string} [options.endpoint=https://www.googleapis.com/oauth2/v4/token]
   * @returns {Promise<accessTokenResponse>}
   */
  static getGoogleAccessToken(keyFileData, scopes = null, options = {}) {
    return _getGoogleAccessToken(
      defaultHttpRequestHandler,
      keyFileData,
      scopes,
      options
    )
  }
  /**
   * Get Google Access Token from gcloud environment
   * @returns {Promise<accessTokenResponse>}
   */
  getGoogleAccessTokenFromGCloudHelper() {
    return _getGoogleAccessTokenFromGCloudHelper()
  }

  /**
   * Get Google Access Token from gcloud environment
   * @returns {Promise<accessTokenResponse>}
   */
  static getGoogleAccessTokenFromGCloudHelper() {
    return _getGoogleAccessTokenFromGCloudHelper()
  }
}

/**
 * Get Google Access Token from service account keyfile
 * @param {string} keyFileData
 * @param {Array<string>} [scopes=['https://www.googleapis.com/auth/userinfo.email']]
 * @param {Object} [options]
 * @param {number} [options.expires=3600]
 * @param {string} [options.impersonate]
 * @param {string} [options.endpoint=https://www.googleapis.com/oauth2/v4/token]
 * @returns {Promise<accessTokenResponse>}
 */
function _getGoogleAccessToken(
  httpRequestHandler,
  keyFileData,
  scopes,
  options
) {
  // TODO: Remove in V2.0
  // Support old interface for expires
  if (typeof scopes === 'number') {
    if (options !== null && typeof options === 'object') {
      options.expires = scopes
    } else {
      options = {
        expires: scopes
      }
    }
    scopes = null
  }

  scopes = scopes ? scopes : ['https://www.googleapis.com/auth/userinfo.email']

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
    exp: unixNow + (options.expires || 3600),
    scope: scopes.join(' ')
  }

  if (options.impersonate) {
    jwtBody.sub = options.impersonate
  }

  let jwt = jwtEncode(keyData.private_key, jwtHeader, jwtBody)

  let formParams = {
    grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
    assertion: jwt
  }
  let formData = Object.keys(formParams)
    .map(key => `${key}=${querystring.escape(formParams[key])}`)
    .join('&')

  // Be pessimistic with expiry time so start time before doing the request
  let now = new Date().getTime()

  // Fetch access token

  return httpRequestHandler(
    'POST',
    options.endpoint || 'https://www.googleapis.com/oauth2/v4/token',
    {
      'Content-Type': 'application/x-www-form-urlencoded'
    },
    formData
  ).then(response => {
    if (response.statusCode === 200) {
      let authResponse = JSON.parse(Buffer.from(response.data).toString('utf8'))

      return {
        accessToken: authResponse.access_token,
        expiresIn: authResponse.expires_in,
        expiresAt: now + authResponse.expires_in * 1000
      }
    } else {
      throw new JwtServiceAuthError('response.statusCode not 200', {
        statusCode: response.statusCode,
        data: Buffer.from(response.data).toString('utf8')
      })
    }
  })
}

function _getGoogleAccessTokenFromGCloudHelper() {
  let [gcloudConfigHelper, resultPromise] = ProcessUtils.runProcessAsync(
    `gcloud`,
    ['config', 'config-helper', '--format=json'],
    { closeStdin: true }
  )

  return resultPromise.then(result => {
    let config = JSON.parse(result.stdout)
    let now = new Date().getTime()
    let expiresAt = new Date(config.credential.token_expiry).getTime()
    return {
      accessToken: config.credential.access_token,
      expiresIn: Math.ceil((expiresAt - now) / 1000),
      expiresAt: expiresAt
    }
  })
}

module.exports = JwtServiceAuth
