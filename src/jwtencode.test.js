// @ts-check
'use strict'

const expect = require('unexpected')
const {
  rsaPublicKeyEncrypted,
  rsaPrivateKeyEncrypted
} = require('./testresources')

const { JwtUtils } = require('./index')

const pubKeys = {
  'test@test.com': {
    '1@RS256': rsaPublicKeyEncrypted,
    '1@RS384': rsaPublicKeyEncrypted,
    '1@RS512': rsaPublicKeyEncrypted
  }
}

const unixNow = Math.floor(Date.now() / 1000)

const jwtHeader = {
  typ: 'JWT',
  alg: 'RS256',
  kid: '1'
}

const jwtBody = {
  aud: 'https://host/oauth/token',
  iss: 'test@test.com',
  iat: unixNow,
  exp: unixNow + 600,
  scope: ['http://stuff', 'http://stuff2']
}

describe('jwtUtils', () => {
  describe('decode', () => {
    it('should faile with invalid header and body', () => {
      expect(
        () => {
          JwtUtils.encode('', '', '')
        },
        'to throw',
        'both header and body should be of type object'
      )
    })
    it('should faile with empty header and body', () => {
      expect(
        () => {
          JwtUtils.encode('', {}, {})
        },
        'to throw',
        'Only alg RS256, RS384, RS512, ES256, ES384 and ES512 are supported'
      )
    })
    it('should succeed with encrypted RSA private key', () => {
      for (let algo of ['RS256', 'RS384', 'RS512']) {
        let customJwtHeader = Object.assign({}, jwtHeader)
        customJwtHeader.alg = algo
        let jwt = JwtUtils.encode(
          rsaPrivateKeyEncrypted,
          customJwtHeader,
          jwtBody,
          'Qwerty1234'
        )
        let decodedJwtBody = JwtUtils.decode(jwt, pubKeys, [
          'https://host/oauth/token'
        ])
        expect(jwtBody, 'to equal', decodedJwtBody)
      }
    })
  })
})
