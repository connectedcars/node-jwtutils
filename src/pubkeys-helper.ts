import { AxiosResponse } from 'axios'

import * as RequestHandler from './default-http-request-handler'
import * as jwkUtils from './jwk-utils'
import type { JwkBody } from './types'

export interface PublicKey {
  publicKey: string
  expiresSkew?: number
  expiresMax?: number
  validators?: Record<string, () => boolean>
}

export type PublicKeys = Record<string, Record<string, string | Buffer | PublicKey>>

interface JwkOptions {
  expiresSkew?: number
  defaultAlgorithms?: string[]
}

type FormattedPublicKeys = Record<string, PublicKey>

export class PubkeysHelper {
  private requestHandler: RequestHandler.HttpRequestHandler

  public constructor(httpRequestHandler?: RequestHandler.HttpRequestHandler) {
    this.requestHandler = httpRequestHandler || RequestHandler.defaultHttpRequestHandler
  }

  public async fetchJwkKeys(url: string, options: JwkOptions = {}): Promise<FormattedPublicKeys | null> {
    const defaultAlgorithms = options.defaultAlgorithms ?? []
    delete options.defaultAlgorithms

    let updatedOptions: Record<string, number> = {}

    if (options.expiresSkew != undefined) {
      updatedOptions = { expiresSkew: options.expiresSkew }
    }

    const result = (await this.requestHandler('GET', url, {}, null)) as AxiosResponse<string>

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
    response: AxiosResponse<string>,
    url: string,
    defaultAlgorithms: string[],
    options: Record<string, number> = {}
  ): FormattedPublicKeys {
    const pubkeysResponse = JSON.parse(Buffer.from(response.data).toString('utf8')) as {
      keys: JwkBody[]
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
}
