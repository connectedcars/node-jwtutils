import { AxiosResponse } from 'axios'
import log from '@connectedcars/logutil'


const { default: axios } = require('axios')

interface ErrorContext {
  url: string
  message: string
  headers: { [key: string]: string }
  status?: number
  data?: unknown
}

export async function defaultHttpRequestHandler(method: string, url: string, headers?: Record<string, unknown>, body?: unknown): Promise<AxiosResponse | null> {
    try {
        const res = await axios({method: method, url: url, headers: headers, data: body})
        return res
    } catch (e) {
       if (e.response && e.response.status === 404) {
        return null
      } else {
        const context: ErrorContext = { url, message: e.message, headers: e.response.headers}
        if (e.response) {
          context.status = e.response.status
          if (e.response.data) {
            context.data = e.response.data
          }
        }
        log.error(`call to ${url} failed: "${e.message}"`, { context })
      }
      return null
    }
}
