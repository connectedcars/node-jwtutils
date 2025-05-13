import axios, { AxiosError, type AxiosRequestConfig, type AxiosResponse } from 'axios'

import { JwtServiceAuthError } from './jwt-service-auth-error'

type Headers = AxiosRequestConfig['headers']

type HttpRequestOptions = Pick<AxiosRequestConfig, 'timeout' | 'maxContentLength' | 'maxBodyLength'>

const DEFAULT_TIMEOUT = 6000
const DEFAULT_MAX_CONTENT_LENGTH = 10 * 1024 * 1024
const DEFAULT_MAX_BODY_LENGTH = 10 * 1024 * 1024

const defaultHttpRequestOptions: HttpRequestOptions = {
  timeout: DEFAULT_TIMEOUT,
  maxContentLength: DEFAULT_MAX_CONTENT_LENGTH,
  maxBodyLength: DEFAULT_MAX_BODY_LENGTH
}

export type HttpRequestHandler = (
  method: string,
  url: string,
  headers?: Headers,
  body?: unknown,
  options?: HttpRequestOptions
) => Promise<AxiosResponse>

export async function defaultHttpRequestHandler(
  method: string,
  url: string,
  headers?: Headers,
  body?: unknown,
  options: HttpRequestOptions = defaultHttpRequestOptions
): Promise<AxiosResponse> {
  try {
    return await axios({ method, url, headers, data: body, ...options })
  } catch (error) {
    if (error instanceof AxiosError) {
      throw new JwtServiceAuthError(error.message, {
        statusCode: error.response?.status || error.response?.status,
        data: error.response?.data
      })
    }

    throw error
  }
}
