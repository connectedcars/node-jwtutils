import { AxiosResponse } from 'axios'
import querystring from 'querystring'

import { defaultHttpRequestHandler } from './defaulthttprequesthandler'
import { JwtServiceAuthError, JwtUtils } from './index'
import * as ProcessUtils from './processutils'

interface Options {
  endpoint?: string
  expires?: number
  impersonate?: string
  command?: string
}

interface AccessToken {
  accessToken: string
  expiresIn: number
  expiresAt: number
}

export class JwtServiceAuth {
  private requestHandler: (
    method: string,
    url: string,
    headers?: Record<string, string | number>,
    body?: unknown
  ) => Promise<AxiosResponse | null>
  private authEndpoint: string | null
  private command: string

  public constructor(
    httpRequestHandler?: (
      method: string,
      url: string,
      headers?: Record<string, string | number>,
      body?: unknown
    ) => Promise<AxiosResponse>,
    options: Options = {}
  ) {
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
  ): Promise<AccessToken> {
    const expires = options.expires ? options.expires : 600

    // Create JWT auth token
    const unixNow = Math.floor(new Date().getTime() / 1000)
    const jwtHeader = {
      typ: 'JWT',
      alg: 'RS256'
    }
    const jwtBody = {
      iat: unixNow,
      exp: unixNow + expires,
      iss: appId
    }

    const jwt = JwtUtils.encode(privateKey, jwtHeader, jwtBody)

    // Fetch access token for installation
    const res = await this.requestHandler(
      'POST',
      this.authEndpoint || `https://api.github.com/app/installations/${installationId}/access_tokens`,
      {
        Authorization: 'Bearer ' + jwt,
        'User-Agent': appName ? appName : 'jwtutils',
        Accept: 'application/vnd.github.machine-man-preview+json'
      },
      undefined
    )
    if (res && res.status === 201) {
      const authResponse = res.data
      const now = new Date().getTime()
      const expiresAt = new Date(authResponse.expires_at).getTime()
      return {
        accessToken: authResponse.token,
        expiresIn: Math.ceil((expiresAt - now) / 1000),
        expiresAt: expiresAt
      }
    } else {
      throw new JwtServiceAuthError(`Fetching github access token returned no response`)
    }
  }

  public async getGoogleAccessTokenFromGCloudHelper(): Promise<AccessToken> {
    const resultPromise = ProcessUtils.runProcessAsync(this.command, ['config', 'config-helper', '--format=json'], {
      closeStdin: true
    })

    return await resultPromise.then(result => {
      const config = JSON.parse(result.stdout)
      const now = new Date().getTime()
      const expiresAt = new Date(config.credential.token_expiry).getTime()
      return {
        accessToken: config.credential.access_token,
        expiresIn: Math.ceil((expiresAt - now) / 1000),
        expiresAt: expiresAt
      }
    })
  }

  public async getGoogleAccessToken(
    keyFileData: string,
    scopes: string[] | number | null = null,
    options: Options = {}
  ): Promise<AccessToken> {
    const mergedConfig = Object.assign({}, options, {
      endpoint: this.authEndpoint || 'https://www.googleapis.com/oauth2/v4/token'
    })
    return await this._getGoogleAccessToken(this.requestHandler, keyFileData, scopes, mergedConfig)
  }

  private async _getGoogleAccessToken(
    httpRequestHandler: (
      method: string,
      url: string,
      headers?: Record<string, string | number>,
      body?: unknown
    ) => Promise<AxiosResponse | null>,
    keyFileData: string,
    scopes: string[] | number | null,
    options: Options = {}
  ): Promise<AccessToken> {
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

    const keyData = JSON.parse(keyFileData)

    if (keyData.type !== 'service_account') {
      throw new Error('Only supports service account keyFiles')
    }

    // Create JWT auth token
    const unixNow = Math.floor(new Date().getTime() / 1000)
    const jwtHeader = {
      typ: 'JWT',
      alg: 'RS256',
      kid: keyData.private_key_id
    }
    const jwtBody: Record<string, string | number> = {
      aud: 'https://www.googleapis.com/oauth2/v4/token',
      iss: keyData.client_email,
      iat: unixNow,
      exp: unixNow + (options.expires || 3600),
      scope: scopes.join(' ')
    }

    if (options.impersonate) {
      jwtBody.sub = options.impersonate
    }

    const jwt = JwtUtils.encode(keyData.private_key, jwtHeader, jwtBody)

    const formParams: Record<string, string> = {
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: jwt
    }
    const formData = Object.keys(formParams)
      .map(key => `${key}=${querystring.escape(formParams[key])}`)
      .join('&')

    // Be pessimistic with expiry time so start time before doing the request
    // Fetch access token
    const res = await httpRequestHandler(
      'POST',
      this.authEndpoint || 'https://www.googleapis.com/oauth2/v4/token',
      {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      formData
    )
    if (res && res.status === 200) {
      const now = new Date().getTime()
      return {
        accessToken: res.data.access_token,
        expiresIn: res.data.expires_in,
        expiresAt: now + res.data.expires_in * 1000
      }
    } else {
      throw new JwtServiceAuthError(`Fetching google access token returned no response`)
    }
  }
}
