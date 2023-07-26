import log from '@connectedcars/logutil'
import axios, { AxiosResponse } from 'axios'
import * as jwkUtils from './jwkutils'
import { defaultHttpRequestHandler } from './defaulthttprequesthandler'

interface ErrorContext {
  url: string
  message: string
  headers: { [key: string]: string }
  status?: number
  data?: unknown
}

interface Options {
  defaultAlgorithms?: string[]
  expiresSkew?: number
}

export class PubkeysHelper {
  private requestHandler: (method: string, url: string, headers?: Record<string, unknown>, body?: unknown) => Promise<AxiosResponse | null>

  constructor(httpRequestHandler?: (method: string, url: string, headers?: Record<string, unknown>, body?: unknown) => Promise<AxiosResponse | null>) {
    if(!httpRequestHandler) {
      this.requestHandler = defaultHttpRequestHandler
      return
    }
    this.requestHandler = httpRequestHandler
  }
  public async fetchJwkKeys(url: string, options: Options = {}): Promise<Record<string, string> | null> {
    const defaultAlgorithms = options.defaultAlgorithms || []
    delete options.defaultAlgorithms

    const result = await this.requestHandler('GET', url, {}, null)
    if (!result) {
      return null
    }
    const pubKeys = this.formatPublicKeys(result.data, url, defaultAlgorithms, options)
    if (!pubKeys) {
      return null
    }
    return pubKeys
  }

  private formatPublicKeys(response: any, url: string, defaultAlgorithms: string[], options: Options = {}): Record<string, string> {
    let pubkeysResponse = JSON.parse(
      Buffer.from(response.data).toString('utf8')
    )
    if (!Array.isArray(pubkeysResponse.keys)) {
      throw new Error(
        `Response from ${url} not in expected format: Missing array property keys`
      )
    }
    if (Object.keys(pubkeysResponse.keys).length === 0) {
      throw new Error(`No keys found in response from ${url}`)
    }

    let pubKeys = {}
    for (const key of pubkeysResponse.keys) {
      let publicKeyPem = jwkUtils.jwkToPem(key)
      let algorithms = key.alg ? [key.alg] : defaultAlgorithms
      for (let algorithm of algorithms) {
        pubKeys[`${key.kid}@${algorithm}`] = Object.assign(
          {
            publicKey: publicKeyPem
          },
          options
        )
      }
    }
    return pubKeys
  }
}