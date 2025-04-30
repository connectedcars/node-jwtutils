import axios, { AxiosResponse } from 'axios'

import { JwtServiceAuthError } from './jwtserviceautherror'

export type HttpRequestHandler = (
  method: string,
  url: string,
  headers?: Record<string, string | number>,
  body?: unknown
) => Promise<AxiosResponse>

export async function DefaultHttpRequestHandler(
  method: string,
  url: string,
  headers?: Record<string, string | number>,
  body?: unknown
): Promise<AxiosResponse> {
  try {
    const res = await axios({ method, url, headers, data: body })
    return res
  } catch (e) {
    throw new JwtServiceAuthError(e.message, {
      statusCode: e.response.statusCode || e.response.status,
      data: e.response.data
    })
  }
}
