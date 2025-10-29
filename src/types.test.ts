import { isJwkBody, isJwtBody, isJwtHeader } from './types'

describe('types', () => {
  describe('isJwtHeader', () => {
    it('returns true for valid jwt headers', () => {
      expect(isJwtHeader({})).toBe(true)
      expect(isJwtHeader({ typ: 'JWT' })).toBe(true)
      expect(isJwtHeader({ typ: 'JWT', hello: 'world' })).toBe(true)
      expect(isJwtHeader({ typ: 'JWT', kid: '1', alg: 'RS256' })).toBe(true)
    })

    it('returns false for invalid jwt headers', () => {
      expect(isJwtHeader(null)).toBe(false)
      expect(isJwtHeader(undefined)).toBe(false)
      expect(isJwtHeader({ typ: true })).toBe(false)
      expect(isJwtHeader({ typ: 'JWT', kid: 1 })).toBe(false)
    })
  })

  describe('isJwtBody', () => {
    it('returns true for valid jwt bodies', () => {
      expect(isJwtBody({})).toBe(true)
      expect(isJwtBody({ iss: 'issuer' })).toBe(true)

      expect(
        isJwtBody({
          iss: 'iss',
          ons: 'ons',
          sub: 'sub',
          aud: 'aud',
          acr: 'acr',
          jti: 'jti',
          sid: 'sid',
          amr: ['amr'],
          exp: 100,
          iat: 100,
          nbf: 100,
          clt: 100,
          email: 'email',
          email_verified: true,
          scope: 'scope'
        })
      ).toBe(true)

      expect(
        isJwtBody({
          iss: 'iss',
          ons: 'ons',
          sub: 'sub',
          aud: ['aud'],
          acr: 'acr',
          jti: 'jti',
          sid: 'sid',
          amr: ['amr'],
          exp: 100,
          iat: 100,
          nbf: 100,
          clt: 100,
          email: 'email',
          email_verified: true,
          scope: ['scope']
        })
      ).toBe(true)

      expect(
        isJwtBody({
          iss: 'iss',
          ons: 'ons',
          sub: 'sub',
          aud: null,
          acr: 'acr',
          jti: 'jti',
          sid: 'sid',
          amr: ['amr'],
          exp: undefined,
          iat: 100,
          nbf: 100,
          clt: 100,
          email: 'email',
          email_verified: true,
          scope: 'scope'
        })
      ).toBe(true)

      // 'sid' not present
      expect(
        isJwtBody({
          iss: 'iss',
          ons: 'ons',
          sub: 'sub',
          aud: null,
          acr: 'acr',
          jti: 'jti',
          amr: ['amr'],
          exp: undefined,
          iat: 100,
          nbf: 100,
          clt: 100,
          email: 'email',
          email_verified: true,
          scope: 'scope'
        })
      ).toBe(true)
    })

    it('returns false for invalid jwt bodies', () => {
      expect(isJwtBody(null)).toBe(false)
      expect(isJwtBody(undefined)).toBe(false)
      expect(isJwtBody({ iss: true })).toBe(false)
      expect(isJwtBody({ amr: 'amr' })).toBe(false)
    })
  })

  describe('isJwkBody', () => {
    it('returns true for valid jwk bodies', () => {
      expect(isJwkBody({ kty: 'kty' })).toBe(true)
      expect(isJwkBody({ kty: 'kty', use: 'jwt' })).toBe(true)

      expect(
        isJwkBody({
          kty: 'kty',
          use: 'use',
          kid: 'kid',
          alg: 'alg',
          e: 'e',
          n: 'n',
          crv: 'crv',
          x: 'x',
          y: 'y'
        })
      ).toBe(true)

      expect(
        isJwkBody({
          kty: 'kty',
          use: 'use',
          kid: null,
          alg: 'alg',
          e: 'e',
          n: undefined,
          crv: 'crv',
          x: 'x',
          y: 'y'
        })
      ).toBe(true)

      // 'alg' not present
      expect(
        isJwkBody({
          kty: 'kty',
          use: 'use',
          kid: null,
          e: 'e',
          n: undefined,
          crv: 'crv',
          x: 'x',
          y: 'y'
        })
      ).toBe(true)
    })

    it('returns false for invalid jwk bodies', () => {
      expect(isJwkBody(null)).toBe(false)
      expect(isJwkBody(undefined)).toBe(false)
      expect(isJwkBody({})).toBe(false)
      expect(isJwkBody({ kty: 100 })).toBe(false)
      expect(isJwkBody({ kty: 'kty', use: false })).toBe(false)
    })
  })
})
