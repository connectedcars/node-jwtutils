import querystring from 'querystring'
import jwtEncode from './jwtencode'
import {JwtServiceAuthError} from './jwtserviceautherror'
import { defaultHttpRequestHandler } from './defaulthttprequesthandler'
import * as ProcessUtils from './processutils'
import { AccessTokenResponse } from '../types/@connectedcars/jwtutils'
import { AxiosResponse } from 'axios'

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

interface Options {
  endpoint?: string
  expires?: number
  impersonate?: string
  command?: string
}

export interface JwtBody {
  iss: string // Issuing authority of this token, i.e. our identity provider
  sub: string // Identifier for the party this token is issued on behalf of
  aud: string // Target audience for this token, i.e. our applications
  exp: number // Timestamp for expiry
  iat: number // Timestamp for issuing date
  scope: string
}

interface GoogleAccessToken {
  accessToken: string
  expiresIn: number
  expiresAt: number
}

export class JwtServiceAuth {
    private requestHandler: (method: string, url: string, headers?: Record<string, unknown>, body?: unknown) => Promise<AxiosResponse | null>
    private authEndpoint: string | null
    private command: string

    constructor(httpRequestHandler?: (method: string, url: string, headers?: Record<string, unknown>, body?: unknown) => Promise<AxiosResponse | null>, options: Options = {}) {
      this.requestHandler = httpRequestHandler || defaultHttpRequestHandler
      this.authEndpoint = options.endpoint || null
      this.command = options.command || 'gcloud'
    }

    public async getGithubAccessToken(
      privateKey: string,
      appId: number,
      installationId: number,
      appName?: string,
      options: Options = {}
    ): Promise<AccessTokenResponse> {
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
      return this.requestHandler(
        'POST',
        this.authEndpoint || `https://api.github.com/app/installations/${installationId}/access_tokens`,
        {
          Authorization: 'Bearer ' + jwt,
          'User-Agent': appName ? appName : 'jwtutils',
          Accept: 'application/vnd.github.machine-man-preview+json'
        },
        undefined
      ).then(response => {
        if (response.statusCode === 201 || response.status === 201) {
          let authResponse = response.data
          let now = new Date().getTime()
          let expiresAt = new Date(authResponse.expires_at).getTime()
          return Promise.resolve({
            accessToken: authResponse.token,
            expiresIn: Math.ceil((expiresAt - now) / 1000),
            expiresAt: expiresAt
          })
        }
      })
    }

    public async getGoogleAccessTokenFromGCloudHelper(): Promise<GoogleAccessToken>  {
      let resultPromise = ProcessUtils.runProcessAsync(
        this.command,
        ['config', 'config-helper', '--format=json'],
        { closeStdin: true }
      )
  
      return await resultPromise.then(result => {
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

    public async getGoogleAccessToken(keyFileData: string, scopes: string[] | number = null, options: Options = {}): Promise<GoogleAccessToken> {
      const mergedConfig = Object.assign({}, options, {
        endpoint: this.authEndpoint || 'https://www.googleapis.com/oauth2/v4/token'
      })
      return await this._getGoogleAccessToken(this.requestHandler, keyFileData, scopes, mergedConfig)
    }

    private async _getGoogleAccessToken(
      httpRequestHandler: (method: string, url: string, headers?: Record<string, unknown>, body?: unknown) => Promise<AxiosResponse | null>,
      keyFileData: string,
      scopes: string[] | number,
      options: Options = {}
    ): Promise<GoogleAccessToken> {
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
        scopes = null as string[]
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
      } as JwtBody
    
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
      // Fetch access token

      return await httpRequestHandler('POST',
      this.authEndpoint || 'https://www.googleapis.com/oauth2/v4/token',
      {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      formData).then(response => {
        if (response.statusCode === 200 || response.status == 200) {
          let now = new Date().getTime()
          return {
            accessToken: response.data.access_token,
            expiresIn: response.data.expires_in,
            expiresAt: now + response.data.expires_in * 1000
          }
        }
      })
  }
}