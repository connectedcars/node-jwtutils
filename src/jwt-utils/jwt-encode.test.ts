import crypto from 'crypto'

import type { PublicKeys } from '../pubkeys-helper'
import {
  ed25519Password,
  ed25519PrivateKey,
  ed25519PrivateKeyEncrypted,
  ed25519PublicKey,
  ed25519PublicKeyFromPassword,
  rsaPrivateKey,
  rsaPrivateKeyEncrypted,
  rsaPublicKeyEncrypted
} from '../test/test-resources'
import type { JwtBody, JwtHeader } from '../types'
import { decode } from './jwt-decode'
import { encode } from './jwt-encode'

const pubKeys: PublicKeys = {
  'test@test.com': {
    '1@RS256': rsaPublicKeyEncrypted,
    '1@RS384': rsaPublicKeyEncrypted,
    '1@RS512': rsaPublicKeyEncrypted,
    '2@EdDSA': ed25519PublicKey,
    '3@EdDSA': ed25519PublicKeyFromPassword
  }
}

const unixNow = Math.floor(Date.now() / 1000)

const jwtHeader: JwtHeader = {
  typ: 'JWT',
  alg: 'RS256',
  kid: '1'
}

const jwtBody: JwtBody = {
  aud: 'https://host/oauth/token',
  iss: 'test@test.com',
  iat: unixNow,
  exp: unixNow + 600,
  scope: ['http://stuff', 'http://stuff2']
}

describe('jwt-encode', () => {
  describe('encode', () => {
    it('should succeed with encrypted RSA private key', () => {
      for (const algo of ['RS256', 'RS384', 'RS512']) {
        const customJwtHeader = Object.assign({}, jwtHeader)
        customJwtHeader.alg = algo
        const jwt = encode(rsaPrivateKeyEncrypted, customJwtHeader, jwtBody, 'Qwerty1234')
        const decodedJwtBody = decode(jwt, pubKeys, ['https://host/oauth/token'])

        expect(jwtBody).toEqual(decodedJwtBody)
      }
    })

    it('checks for wrong alg', () => {
      const customJwtHeader = { ...jwtHeader }
      customJwtHeader.alg = 'HS128'

      expect(() => encode('', customJwtHeader, jwtBody)).toThrow(
        'Only alg RS256, RS384, RS512, ES256, ES384, ES512, HS256, HS384 and HS512 are supported'
      )
    })

    it('should fail with empty header and body', () => {
      expect(() => encode('', {}, {})).toThrow(
        'Only alg RS256, RS384, RS512, ES256, ES384, ES512, HS256, HS384 and HS512 are supported'
      )
    })

    it('should fail with missing key for signing algorithm', () => {
      expect(() => encode('', { alg: 'RS256' }, {}, 'key')).toThrow('privateKey can not be null for RS256')
    })

    it('should fail with missing key for hmac algorithm', () => {
      expect(() => encode('', { alg: 'HS256' }, {}, null)).toThrow('privateKeyPassword can not be null for HS256')
    })

    it('should fail when passing a crypto.KeyObject and a private key password', () => {
      expect(() => encode(crypto.createPrivateKey(rsaPrivateKey), { alg: 'RS256' }, {}, 'secret')).toThrow(
        'Cannot pass both privateKey as crypto.KeyObject and privateKeyPassword'
      )
    })

    it('should succeed with ed25519 private key', async () => {
      const customJwtHeader = Object.assign({}, jwtHeader, { alg: 'EdDSA', kid: '2' })
      const jwt = encode(ed25519PrivateKey, customJwtHeader, jwtBody)
      const decodedJwtBody = decode(jwt, pubKeys, ['https://host/oauth/token'])

      expect(jwtBody).toEqual(decodedJwtBody)
    })

    it('should succeed with encrypted ed25519 private key', async () => {
      const customJwtHeader = Object.assign({}, jwtHeader, { alg: 'EdDSA', kid: '3' })
      const jwt = encode(ed25519PrivateKeyEncrypted, customJwtHeader, jwtBody, ed25519Password)
      const decodedJwtBody = decode(jwt, pubKeys, ['https://host/oauth/token'])

      expect(jwtBody).toEqual(decodedJwtBody)
    })

    it('should fail when passing a crypto.KeyObject and a private key password for ed25519', () => {
      expect(() => encode(crypto.createPrivateKey(ed25519PrivateKey), { alg: 'EdDSA' }, {}, 'secret')).toThrow(
        'Cannot pass both privateKey as crypto.KeyObject and privateKeyPassword'
      )
    })
  })
})
