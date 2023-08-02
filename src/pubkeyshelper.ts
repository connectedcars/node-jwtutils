import { AxiosResponse } from 'axios'

import { defaultHttpRequestHandler } from './defaulthttprequesthandler'
import { PublicKey } from './index'
import * as jwkUtils from './jwkutils'

interface Options {
  expiresSkew?: number
  defaultAlgorithms?: string[]
}

export class PubkeysHelper {
  private requestHandler: (
    method: string,
    url: string,
    headers?: Record<string, string | number>,
    body?: unknown
  ) => Promise<AxiosResponse>

  public constructor(
    httpRequestHandler?: (
      method: string,
      url: string,
      headers?: Record<string, string | number>,
      body?: unknown
    ) => Promise<AxiosResponse>
  ) {
    this.requestHandler = httpRequestHandler || defaultHttpRequestHandler
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

    const pubKeys = this.formatPublicKeys(result.data, url, defaultAlgorithms, updatedOptions)
    if (!pubKeys) {
      return null
    }
    return pubKeys
  }

  private formatPublicKeys(
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    response: any,
    url: string,
    defaultAlgorithms: string[],
    options: Record<string, number> = {}
  ): Record<string, PublicKey> {
    const pubkeysResponse = JSON.parse(Buffer.from(response.data).toString('utf8'))
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
