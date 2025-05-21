import type { AxiosResponse } from 'axios'
import querystring from 'querystring'

import { JwtServiceAuthError, jwtUtils } from '.'
import { defaultHttpRequestHandler, type HttpRequestHandler } from './default-http-request-handler'
import type { JwtBody, JwtHeader } from './types'
import { runProcessAsync } from './utils/process'

export interface JwtServiceAuthOptions {
  endpoint?: string
  expires?: number
  impersonate?: string
  command?: string
}

export interface AccessToken {
  accessToken: string
  expiresIn: number
  expiresAt: number
}

interface GithubAccessTokenResponse {
  expires_at: string
  token: string
}

interface GoogleAccessTokenOutput {
  credential: {
    token_expiry: string
    access_token: string
  }
}

interface GoogleAccessTokenResponse {
  access_token: string
  expires_in: number
}

interface KeyData {
  type: string
  private_key: string
  private_key_id: string
  client_email: string
}

export class JwtServiceAuth {
  private requestHandler: HttpRequestHandler
  private authEndpoint: string | null
  private command: string

  public constructor(httpRequestHandler?: HttpRequestHandler, options: JwtServiceAuthOptions = {}) {
    this.requestHandler = httpRequestHandler ?? defaultHttpRequestHandler
    this.authEndpoint = options.endpoint || null
    this.command = options.command || 'gcloud'
  }

  public static async getGoogleAccessTokenFromGCloudHelper(): Promise<AccessToken> {
    return JwtServiceAuth.getGoogleAccessTokenFromGCloudHelperImpl('gcloud')
  }

  private static async getGoogleAccessTokenFromGCloudHelperImpl(command: string): Promise<AccessToken> {
    const result = await runProcessAsync(command, ['config', 'config-helper', '--format=json'], {
      closeStdin: true
    })

    const config = JSON.parse(result.stdout) as GoogleAccessTokenOutput
    const now = new Date().getTime()
    const expiresAt = new Date(config.credential.token_expiry).getTime()

    return {
      accessToken: config.credential.access_token,
      expiresIn: Math.ceil((expiresAt - now) / 1000),
      expiresAt
    }
  }

  public async getGithubAccessToken(
    privateKey: string,
    appId: number,
    installationId: number,
    appName?: string,
    options: JwtServiceAuthOptions = {}
  ): Promise<AccessToken> {
    const expires = options.expires ? options.expires : 600
    const unixNow = Math.floor(new Date().getTime() / 1000)

    const jwtHeader: JwtHeader = {
      typ: 'JWT',
      alg: 'RS256'
    }

    const jwtBody = {
      iat: unixNow,
      exp: unixNow + expires,
      iss: String(appId)
    }

    const jwt = jwtUtils.encode(privateKey, jwtHeader, jwtBody)
    const endpoint = this.authEndpoint || `https://api.github.com/app/installations/${installationId}/access_tokens`
    const headers = {
      Authorization: 'Bearer ' + jwt,
      'User-Agent': appName ? appName : 'jwtutils',
      Accept: 'application/vnd.github.machine-man-preview+json'
    }

    // Fetch access token for installation
    const response = (await this.requestHandler('POST', endpoint, headers)) as AxiosResponse<GithubAccessTokenResponse>

    if (response && response.status === 201) {
      const authResponse = response.data
      const now = new Date().getTime()
      const expiresAt = new Date(authResponse.expires_at).getTime()

      return {
        accessToken: authResponse.token,
        expiresIn: Math.ceil((expiresAt - now) / 1000),
        expiresAt
      }
    } else {
      throw new JwtServiceAuthError('Fetching github access token returned no response')
    }
  }

  public async getGoogleAccessTokenFromGCloudHelper(): Promise<AccessToken> {
    return JwtServiceAuth.getGoogleAccessTokenFromGCloudHelperImpl(this.command)
  }

  public async getGoogleAccessToken(
    keyFileData: string,
    scopes: string[] | number | null = null,
    options: JwtServiceAuthOptions = {}
  ): Promise<AccessToken> {
    const mergedConfig = {
      ...options,
      endpoint: this.authEndpoint || 'https://www.googleapis.com/oauth2/v4/token'
    }

    return this._getGoogleAccessToken(this.requestHandler, keyFileData, scopes, mergedConfig)
  }

  private async _getGoogleAccessToken(
    httpRequestHandler: HttpRequestHandler,
    keyFileData: string,
    scopes: string[] | number | null,
    options: JwtServiceAuthOptions = {}
  ): Promise<AccessToken> {
    // TODO: Remove in V2.0
    // Support old interface for expires
    if (typeof scopes === 'number') {
      if (options !== null && typeof options === 'object') {
        options.expires = scopes
      } else {
        options = { expires: scopes }
      }

      scopes = null
    }

    scopes = scopes ? scopes : ['https://www.googleapis.com/auth/userinfo.email']

    const keyData = JSON.parse(keyFileData) as KeyData

    if (keyData.type !== 'service_account') {
      throw new Error('Only supports service account keyFiles')
    }

    const unixNow = Math.floor(new Date().getTime() / 1000)

    const jwtHeader: JwtHeader = {
      typ: 'JWT',
      alg: 'RS256',
      kid: keyData.private_key_id
    }

    const jwtBody: JwtBody = {
      aud: 'https://www.googleapis.com/oauth2/v4/token',
      iss: keyData.client_email,
      iat: unixNow,
      exp: unixNow + (options.expires || 3600),
      scope: scopes.join(' ')
    }

    if (options.impersonate) {
      jwtBody.sub = options.impersonate
    }

    const jwt = jwtUtils.encode(keyData.private_key, jwtHeader, jwtBody)

    const formParams: Record<string, string> = {
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: jwt
    }

    const formData = Object.keys(formParams)
      .map(key => `${key}=${querystring.escape(formParams[key])}`)
      .join('&')
    const endpoint = this.authEndpoint || 'https://www.googleapis.com/oauth2/v4/token'
    const headers = {
      'Content-Type': 'application/x-www-form-urlencoded'
    }

    // Be pessimistic with expiry time so start time before doing the request
    const now = new Date().getTime()

    // Fetch access token
    const response = (await httpRequestHandler(
      'POST',
      endpoint,
      headers,
      formData
    )) as AxiosResponse<GoogleAccessTokenResponse>

    if (response && response.status === 200) {
      return {
        accessToken: response.data.access_token,
        expiresIn: response.data.expires_in,
        expiresAt: now + response.data.expires_in * 1000
      }
    } else {
      throw new JwtServiceAuthError('Fetching google access token returned no response')
    }
  }
}
