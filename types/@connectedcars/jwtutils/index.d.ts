// TypeScript Version: 3.0

export class JwtVerifyError extends Error {
  innerError: Error
  constructor(message: string, innerError?: Error)
}

export interface JwtDecodeOptions {
  expiresSkew?: number
  expiresMax?: number
  nbfIatSkew?: number
  fixup?: (header: any, body: any) => void
}

export interface getGithubAccessTokenOptions {
  expires: number
}

export interface getGoogleAccessTokenOptions {
  impersonate?: string
  expires?: number
}

export namespace JwtUtils {
  function encode(privateKey: string | null, header: any, body: any, privateKeyPassword?: string): string
  function decode(jwt: string, publicKeys: any, audiences: string[], options?: JwtDecodeOptions): any
}

export type JWK = RsaJWK | EcJWK

export interface RsaJWK {
  kty: 'RSA'
  n: string,
  e: string
}

export interface EcJWK {
  kty: 'EC'
  crv: string,
  x: string
  y: string
}

export namespace JwkUtils {
  function rsaPublicJwkToPem(rsaPublicKeyJwk: RsaJWK): string
  function ecPublicKeyJwkToPem(rsaPublicKeyJwk: EcJWK): string
  function jwkToPem(jwk: JWK): string
}

export interface HttpHandlerResponse {
  statusCode: number
  statusMessage: string
  data: Buffer
  headers: object
}

export interface AccessTokenResponse {
  accessToken: string
  expiresIn: number
  expiresAt: number
}

export class JwtServiceAuth {
  constructor(httpRequestHandler?: (method: string, url: string, headers: object, body: string | Buffer) => Promise<HttpHandlerResponse>, options?: { endpoint?: string })
  getGithubAccessToken(privateKey: string, appId: string, installationId: string, appName: string, options?: getGithubAccessTokenOptions): Promise<AccessTokenResponse>
  getGoogleAccessTokenFromGCloudHelper(): Promise<AccessTokenResponse>
  static getGoogleAccessTokenFromGCloudHelper(): Promise<AccessTokenResponse>
  getGoogleAccessToken(googleServiceAccount: string, scopes: string[], options?: getGoogleAccessTokenOptions): Promise<AccessTokenResponse>
  static getGoogleAccessToken(googleServiceAccount: string, scopes: string[], options?: getGoogleAccessTokenOptions): Promise<AccessTokenResponse>
}

export interface JwtAuthMiddlewareOptions {
  allowAnonymous: boolean
}

export function JwtAuthMiddleware(pubKeys: any, revokedTokens: any, audiences: string[], mapper: (user: any) => void, options?: JwtAuthMiddlewareOptions): (request: any, response: any, next: () => void) => void

export interface JwkKeysOptions {
  defaultAlgoritms?: string[]
  [x: string]: any // Allow any other fields
}
export class PubkeysHelper {
  static fetchJwkKeys: (url: string, options?: JwkKeysOptions) => Promise<any>
  public fetchJwkKeys: (url: string, options?: JwkKeysOptions) => Promise<any>
  constructor(
    httpRequestHandler?: (
      method: string,
      url: string,
      headers: any,
      body: Buffer | string
    ) => Promise<any>
  )
}
