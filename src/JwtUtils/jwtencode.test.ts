import { JwtUtils } from '../index'
import { JwtVerifyError } from '../jwtverifyerror'
import { rsaPrivateKeyEncrypted, rsaPublicKeyEncrypted } from '../testresources'

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
  describe('encode', () => {
    it('should succeed with encrypted RSA private key', () => {
      for (const algo of ['RS256', 'RS384', 'RS512']) {
        const customJwtHeader = Object.assign({}, jwtHeader)
        customJwtHeader.alg = algo
        const jwt = JwtUtils.encode(rsaPrivateKeyEncrypted, customJwtHeader, jwtBody, 'Qwerty1234')
        const decodedJwtBody = JwtUtils.decode(jwt, pubKeys, ['https://host/oauth/token'])
        expect(jwtBody).toEqual(decodedJwtBody)
      }
    })
    it('should fail with empty header and body', () => {
      expect(() => JwtUtils.encode('', {}, {})).toThrow(
        new JwtVerifyError('Only alg RS256, RS384, RS512, ES256, ES384, ES512, HS256, HS384 and HS512 are supported')
      )
    })
    it('should fail with missing key', () => {
      expect(() => JwtUtils.encode('', { alg: 'RS256' }, {}, 'key')).toThrow(
        new JwtVerifyError('privateKey can not be null for RS256')
      )
    })
  })
})
