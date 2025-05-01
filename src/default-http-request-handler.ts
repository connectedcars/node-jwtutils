import axios, { AxiosError, AxiosResponse } from 'axios'

import { JwtServiceAuthError } from './jwt-serviceauth-error'

export type HttpRequestHandler = (
  method: string,
  url: string,
  headers?: Record<string, string | number>,
  body?: unknown
) => Promise<AxiosResponse | undefined>

export async function DefaultHttpRequestHandler(
  method: string,
  url: string,
  headers?: Record<string, string | number>,
  body?: unknown
): Promise<AxiosResponse | undefined> {
  try {
    const res = await axios({ method, url, headers, data: body })
    return res
  } catch (error) {
    if (error instanceof AxiosError) {
      throw new JwtServiceAuthError(error.message, {
        statusCode: error.response?.status || error.response?.status,
        data: error.response?.data
      })
    }
  }

  return undefined
}
