import { AxiosResponse } from 'axios'

import * as RequestHandler from './default-http-request-handler'
import { PublicKey } from './index'
import * as jwkUtils from './jwk-utils'

interface Options {
  expiresSkew?: number
  defaultAlgorithms?: string[]
}

export interface JwkBody {
  kid: string
  kty: string
  use: string
  alg: string
  e: string
  n: string
  crv?: string
  x?: string
  y?: string
}

export class PubkeysHelper {
  private requestHandler: RequestHandler.HttpRequestHandler

  public constructor(httpRequestHandler?: RequestHandler.HttpRequestHandler) {
    this.requestHandler = httpRequestHandler || RequestHandler.DefaultHttpRequestHandler
  }

  public async fetchJwkKeys(url: string, options: Options = {}): Promise<Record<string, PublicKey> | null> {
    const defaultAlgorithms = options.defaultAlgorithms || []
    delete options.defaultAlgorithms

    let updatedOptions: Record<string, number> = {}
    if (options.expiresSkew != undefined) {
      updatedOptions = { expiresSkew: options.expiresSkew }
    }

    const result = await this.requestHandler('GET', url, {}, null)
    if (!result) {
      return null
    }

    const pubKeys = this.formatPublicKeys(result, url, defaultAlgorithms, updatedOptions)
    if (!pubKeys) {
      return null
    }
    return pubKeys
  }

  private formatPublicKeys(
    response: AxiosResponse,
    url: string,
    defaultAlgorithms: string[],
    options: Record<string, number> = {}
  ): Record<string, PublicKey> {
    const pubkeysResponse = JSON.parse(Buffer.from(response.data as string).toString('utf8')) as {
      keys: JwkBody[]
    }
    if (!Array.isArray(pubkeysResponse.keys)) {
      throw new Error(`Response from ${url} not in expected format: Missing array property keys`)
    }
    if (Object.keys(pubkeysResponse.keys).length === 0) {
      throw new Error(`No keys found in response from ${url}`)
    }

    const pubKeys: Record<string, PublicKey> = {}
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
}
