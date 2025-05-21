import { AxiosResponse } from 'axios'
import crypto from 'crypto'

import * as RequestHandler from './default-http-request-handler'
import * as jwkUtils from './jwk-utils'
import type { PublicKey } from './jwt-utils/decode-validators'
import type { JwkBody } from './types'

export type PublicKeys = Record<string, Record<string, string | Buffer | PublicKey | crypto.KeyObject>>

export interface JwkOptions {
  expiresSkew?: number
  defaultAlgorithms?: string[]
}

export type FormattedPublicKeys = Record<string, PublicKey>

export class PubkeysHelper {
  private requestHandler: RequestHandler.HttpRequestHandler

  public constructor(httpRequestHandler?: RequestHandler.HttpRequestHandler) {
    this.requestHandler = httpRequestHandler ?? RequestHandler.defaultHttpRequestHandler
  }

  public static async fetchJwkKeys(url: string, options: JwkOptions = {}): Promise<FormattedPublicKeys | null> {
    return PubkeysHelper.fetchJwkKeysImpl(RequestHandler.defaultHttpRequestHandler, url, options)
  }

  private static formatPublicKeys(
    response: AxiosResponse<unknown>,
    url: string,
    defaultAlgorithms: string[],
    options: Pick<JwkOptions, 'expiresSkew'> = {}
  ): FormattedPublicKeys {
    let pubkeysResponse

    // Axios requests automatically convert json responses to objects but a
    // custom request handler might return something else
    if (typeof response.data === 'string' || Array.isArray(response.data)) {
      pubkeysResponse = JSON.parse(Buffer.from(response.data).toString('utf8')) as {
        keys: JwkBody[]
      }
    } else {
      pubkeysResponse = response.data as { keys: JwkBody[] }
    }

    if (!Array.isArray(pubkeysResponse.keys)) {
      throw new Error(`Response from ${url} not in expected format: Missing array property keys`)
    }

    if (Object.keys(pubkeysResponse.keys).length === 0) {
      throw new Error(`No keys found in response from ${url}`)
    }

    const pubKeys: FormattedPublicKeys = {}

    for (const key of pubkeysResponse.keys) {
      const publicKeyPem = jwkUtils.jwkToPem(key)
      const algorithms = key.alg ? [key.alg] : defaultAlgorithms

      for (const algorithm of algorithms) {
        pubKeys[`${key.kid}@${algorithm}`] = {
          publicKey: publicKeyPem,
          expiresSkew: options.expiresSkew
        }
      }
    }

    return pubKeys
  }

  private static async fetchJwkKeysImpl(
    requestHandler: RequestHandler.HttpRequestHandler,
    url: string,
    options: JwkOptions = {}
  ): Promise<FormattedPublicKeys | null> {
    const defaultAlgorithms = options.defaultAlgorithms ?? []
    delete options.defaultAlgorithms

    const updatedOptions: Pick<JwkOptions, 'expiresSkew'> = {}

    if (options.expiresSkew != undefined) {
      updatedOptions.expiresSkew = options.expiresSkew
    }

    const result = await requestHandler('GET', url, {}, null)

    if (!result) {
      return null
    }

    const pubKeys = this.formatPublicKeys(result, url, defaultAlgorithms, updatedOptions)

    if (!pubKeys) {
      return null
    }

    return pubKeys
  }

  public async fetchJwkKeys(url: string, options: JwkOptions = {}): Promise<FormattedPublicKeys | null> {
    return PubkeysHelper.fetchJwkKeysImpl(this.requestHandler, url, options)
  }
}
