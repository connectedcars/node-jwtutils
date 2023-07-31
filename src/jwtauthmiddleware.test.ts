// import expect from 'unexpected'
import { ecPrivateKey, ecPublicKey } from './testresources'

import { AxiosResponse } from 'axios'
import {JwtServiceAuthError} from './jwtserviceautherror'
import express from 'express'
import app = express
import http, { Server } from 'http'
import { JwtAuthMiddlewareServer } from './jwtauthmiddleware-test-server'
//todo: grace fix this import/export
import jwtEncode from './jwtencode'
// import { JwtUtils, JwtAuthMiddleware, JwtVerifyError } from './index'
const { default: axios } = require('axios')


const jwtHeader = {
  typ: 'JWT',
  alg: 'ES256',
  kid: '1'
}

const unixNow = Math.floor(Date.now() / 1000)

const jwtBody = {
  aud: 'http://localhost/',
  iss: 'http://localhost/oauth/token',
  jti: 'jtiValid',
  iat: unixNow,
  exp: unixNow + 600,
  scope: ['http://stuff', 'http://stuff2'],
  sub: 'subject@domain.tld',
  email: 'test@domain.tld'
}


describe('jwtMiddleware', () => {
  let server: JwtAuthMiddlewareServer
  function getServerAddress() {
    const address = server.getServer().address()
    if (!address || typeof address === 'string') {
      throw new Error('Resolving server port failed')
    }
    return `http://localhost:${address.port}`
  }
  
 
  beforeEach(async function() {
    server = new JwtAuthMiddlewareServer({port: 0})
    await server.start()
  })
  afterEach(async function () {
    if (server) {
      await server.stop()
    }
  })

  describe('authentication', () => {
    it('should return ok', async () => {
      const jwt = jwtEncode(ecPrivateKey, jwtHeader, jwtBody)
      const responsePromise = await doRequest('GET', `${getServerAddress()}/`, {
        Authorization: 'Bearer ' + jwt,
        Accept: 'application/json',
        'User-Agent': 'test'
      })
      expect(responsePromise).toHaveProperty('data', 'Hello subject@domain.tld')
      expect(responsePromise).toHaveProperty('status', 200)
    })

    it('should return ok for anonymous', async () => {
      const responsePromise = await doRequest('GET', `${getServerAddress()}/anonymous`, {
        Accept: 'application/json',
        'User-Agent': 'test'
      })
   
      expect(responsePromise).toHaveProperty('data', 'Hello anonymous')
      expect(responsePromise).toHaveProperty('status', 200)
     
    })
    it('should fail for anonymous with invalid token', async () => {
      const customJwtBody = Object.assign({}, jwtBody)
      delete customJwtBody.sub
      const jwt = jwtEncode(ecPrivateKey, jwtHeader, customJwtBody)
      await expect(doRequest('GET', `${getServerAddress()}/anonymous`, {
        Authorization: 'Bearer ' + jwt,
        Accept: 'application/json',
        'User-Agent': 'test'
      })).rejects.toThrow(new JwtServiceAuthError('Request failed with status code 401'))
    })
    it('should return ok with a new e-mail', async () => {
      const jwt = jwtEncode(ecPrivateKey, jwtHeader, jwtBody)
      const responsePromise = await doRequest('GET', `${getServerAddress()}/mapped`, {
        Authorization: 'Bearer ' + jwt,
        Accept: 'application/json',
        'User-Agent': 'test'
      })
      expect(responsePromise).toHaveProperty('data', 'Hello test@domain.tld')
      expect(responsePromise).toHaveProperty('status', 200)
    })
    it('should fail because of missing sub', async () => {
      const customJwtBody = Object.assign({}, jwtBody)
      delete customJwtBody.sub
      const jwt = jwtEncode(ecPrivateKey, jwtHeader, customJwtBody)
      await expect(doRequest('GET', `${getServerAddress()}/`, {
        Authorization: 'Bearer ' + jwt,
        Accept: 'application/json',
        'User-Agent': 'test'
      })).rejects.toThrow(new JwtServiceAuthError('Request failed with status code 401'))
    })
    it('should fail because of revoked token', async () => {
      const customJwtBody = Object.assign({}, jwtBody)
      customJwtBody.jti = 'jtiRevoked'
      const jwt = jwtEncode(ecPrivateKey, jwtHeader, customJwtBody)
      await expect(doRequest('GET', `${getServerAddress()}/`, {
        Authorization: 'Bearer ' + jwt,
        Accept: 'application/json',
        'User-Agent': 'test'
      })).rejects.toThrow(new JwtServiceAuthError('Request failed with status code 401'))
    })
    it('should fail because of malform JSON', async () => {
      const jwt = jwtEncode(ecPrivateKey, jwtHeader, jwtBody)
      await expect(doRequest('GET', `${getServerAddress()}/`, {
        Authorization: 'Bearer ' + jwt.substr(2),
        Accept: 'application/json',
        'User-Agent': 'test'
      })).rejects.toThrow(new JwtServiceAuthError('Request failed with status code 401'))
    })
    it('should fail with unknown pubkey id', async () => {
      const customJwtHeader = Object.assign({}, jwtHeader)
      customJwtHeader.kid = '2'
      const jwt = jwtEncode(ecPrivateKey, customJwtHeader, jwtBody)
      await expect(doRequest('GET', `${getServerAddress()}/`, {
        Authorization: 'Bearer ' + jwt,
        Accept: 'application/json',
        'User-Agent': 'test'
      })).rejects.toThrow(new JwtServiceAuthError('Request failed with status code 401'))
    })
    it('should fail with not allowed because it has no token', async () => {
      await expect(doRequest('GET', `${getServerAddress()}/`, {
        Accept: 'application/json',
        'User-Agent': 'test'
      })).rejects.toThrow(new JwtServiceAuthError('Request failed with status code 401'))
    })
    it('should fail with async error', async () => {
      const customJwtBody = Object.assign({}, jwtBody)
      customJwtBody.sub = 'error'
      const jwt = jwtEncode(ecPrivateKey, jwtHeader, customJwtBody)
      await expect(doRequest('GET', `${getServerAddress()}/async`, {
        Authorization: 'Bearer ' + jwt,
        Accept: 'application/json',
        'User-Agent': 'test',
        'X-Error': 'Async error'
      })).rejects.toThrow(new JwtServiceAuthError('Request failed with status code 401'))
    })
    it('should success with async', async () => {
      const jwt = jwtEncode(ecPrivateKey, jwtHeader, jwtBody)
      const responsePromise = await doRequest('GET', `${getServerAddress()}/async`, {
        Authorization: 'Bearer ' + jwt,
        Accept: 'application/json',
        'User-Agent': 'test'
      })
      expect(responsePromise).toHaveProperty('data', 'Async response')
      expect(responsePromise).toHaveProperty('status', 200)
    })
  })
})


async function doRequest(method: string, url: string, headers?: Record<string, unknown>, body?: unknown): Promise<AxiosResponse> {
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

