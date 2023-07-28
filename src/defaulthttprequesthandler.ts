import { AxiosResponse } from 'axios'
import {JwtServiceAuthError} from './jwtserviceautherror'



const { default: axios } = require('axios')

export async function defaultHttpRequestHandler(method: string, url: string, headers?: Record<string, unknown>, body?: unknown): Promise<AxiosResponse> {
    try {
        const res = await axios({method: method, url: url, headers: headers, data: body})
        return res
    } catch (e) {
        throw new JwtServiceAuthError(e.message, {
          statusCode: e.response.statusCode || e.response.status,
          data: e.response.data
        })
      
    }
}
