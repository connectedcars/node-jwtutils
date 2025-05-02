import axios, { AxiosError, type AxiosRequestConfig, type AxiosResponse } from 'axios'

import { JwtServiceAuthError } from './jwt-service-auth-error'

type Headers = AxiosRequestConfig['headers']

export type HttpRequestHandler = (
  method: string,
  url: string,
  headers?: Headers,
  body?: unknown
) => Promise<AxiosResponse>

export async function defaultHttpRequestHandler(
  method: string,
  url: string,
  headers?: Headers,
  body?: unknown
): Promise<AxiosResponse> {
  try {
    return await axios({ method, url, headers, data: body })
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
