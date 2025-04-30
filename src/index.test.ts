import { JwtUtils, JwtVerifyError, PublicKey } from './index'
import { Options } from './jwt-utils/jwtdecode'
import { ecPrivateKey, ecPublicKey, rsaOtherPublicKey, rsaPrivateKey, rsaPublicKey } from './testresources'

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

const pubKeys: Record<string, Record<string, string | PublicKey>> = {
  'test@test.com': {
    'default@RS256': rsaPublicKey,
    '1@RS256': rsaPublicKey,
    '1@RS384': rsaPublicKey,
    '1@RS512': rsaPublicKey,
    '1@ES256': ecPublicKey,
    '1@ES384': ecPublicKey,
    '1@ES512': ecPublicKey,
    '2@RS256': rsaOtherPublicKey,
    '4@RS256': rsaOtherPublicKey.substr(2),
    '2@HS256': 'sharedkey',
    '2@HS384': 'sharedkey',
    '2@HS512': 'sharedkey',
    '5@HS256': 'wrongkey'
  },
  'test@custom.com': {
    '1@RS256': {
      publicKey: rsaPublicKey,
      expiresSkew: 600,
      expiresMax: 86400
    }
  }
}

describe('jwtUtils', () => {
  describe('encode/decode', () => {
    it('success with RSA at RS256, RS384 and RS512', () => {
      for (const algo of ['RS256', 'RS384', 'RS512']) {
        const customJwtHeader = { ...jwtHeader }
        customJwtHeader.alg = algo
        const jwt = JwtUtils.encode(rsaPrivateKey, customJwtHeader, jwtBody)
        const decodedJwtBody = JwtUtils.decode(jwt, pubKeys, ['https://host/oauth/token'])
        expect(jwtBody).toEqual(decodedJwtBody)
      }
    })
    it('success with ECDSA at ES256, ES384 and ES512', () => {
      for (const algo of ['ES256', 'ES384', 'ES512']) {
        const customJwtHeader = { ...jwtHeader }
        customJwtHeader.alg = algo
        const jwt = JwtUtils.encode(ecPrivateKey, customJwtHeader, jwtBody)
        const decodedJwtBody = JwtUtils.decode(jwt, pubKeys, ['https://host/oauth/token'])
        expect(jwtBody).toEqual(decodedJwtBody)
      }
    })
    it('success with HS256, HS384 and HS512', () => {
      for (const algo of ['HS256', 'HS384', 'HS512']) {
        const customJwtHeader = { ...jwtHeader }
        customJwtHeader.kid = '2'
        customJwtHeader.alg = algo
        const jwt = JwtUtils.encode('', customJwtHeader, jwtBody, 'sharedkey')
        const decodedJwtBody = JwtUtils.decode(jwt, pubKeys, ['https://host/oauth/token'])
        expect(jwtBody).toEqual(decodedJwtBody)
      }
    })
    it('success without kid', () => {
      const customJwtHeader = { typ: jwtHeader.typ, alg: jwtHeader.alg }
      const jwt = JwtUtils.encode(rsaPrivateKey, customJwtHeader, jwtBody)
      const decodedJwtBody = JwtUtils.decode(jwt, pubKeys, ['https://host/oauth/token'])
      expect(jwtBody).toEqual(decodedJwtBody)
    })
    it('success with array aud', () => {
      const customJwtBody = { ...jwtBody, aud: ['https://myhost/oauth/token', 'https://host/oauth/token'] }
      const jwt = JwtUtils.encode(rsaPrivateKey, jwtHeader, customJwtBody)
      const decodedJwtBody = JwtUtils.decode(jwt, pubKeys, ['https://host/oauth/token'])
      expect(customJwtBody).toEqual(decodedJwtBody)
    })
    it('success with expired token', () => {
      const customJwtBody = { ...jwtBody }
      customJwtBody.iss = 'test@custom.com'
      customJwtBody.exp -= 600
      const jwt = JwtUtils.encode(rsaPrivateKey, jwtHeader, customJwtBody)
      const decodedJwtBody = JwtUtils.decode(jwt, pubKeys, ['https://host/oauth/token'])
      expect(customJwtBody).toEqual(decodedJwtBody)
    })
    it('token outside maximum expires', () => {
      const customJwtBody = { ...jwtBody }
      customJwtBody.iss = 'test@custom.com'
      customJwtBody.exp += 172800
      const jwt = JwtUtils.encode(rsaPrivateKey, jwtHeader, customJwtBody)
      expect(() => JwtUtils.decode(jwt, pubKeys, ['https://host/oauth/token'])).toThrow(
        new JwtVerifyError('Expires in the future by more than 86400 seconds')
      )
    })
    it('token outside maximum expires using decode options', () => {
      const customJwtBody = { ...jwtBody }
      customJwtBody.exp += 172800
      const jwt = JwtUtils.encode(rsaPrivateKey, jwtHeader, customJwtBody)
      expect(() =>
        JwtUtils.decode(jwt, pubKeys, ['https://host/oauth/token'], {
          expiresMax: 600
        } as Options)
      ).toThrow(new JwtVerifyError('Expires in the future by more than 600 seconds'))
    })
    it('token outside maximum expires using nbf', () => {
      const customJwtBody = { ...jwtBody, exp: jwtBody.exp + 172800, nbf: jwtBody.iat }
      const jwt = JwtUtils.encode(rsaPrivateKey, jwtHeader, customJwtBody)
      expect(() =>
        JwtUtils.decode(jwt, pubKeys, ['https://host/oauth/token'], {
          expiresMax: 600
        } as Options)
      ).toThrow(new JwtVerifyError('Expires in the future by more than 600 seconds'))
    })
    it('token outside maximum expires using unixNow', () => {
      const customJwtBody = { ...jwtBody, exp: jwtBody.exp + 172800 }
      const jwt = JwtUtils.encode(rsaPrivateKey, jwtHeader, customJwtBody)
      expect(() =>
        JwtUtils.decode(jwt, pubKeys, ['https://host/oauth/token'], {
          expiresMax: 600
        } as Options)
      ).toThrow(new JwtVerifyError('Expires in the future by more than 600 seconds'))
    })
    it('unknown aud', () => {
      const jwt = JwtUtils.encode(rsaPrivateKey, jwtHeader, jwtBody)
      expect(() => JwtUtils.decode(jwt, pubKeys, ['https://myhost/oauth/token'])).toThrow(
        new JwtVerifyError(`Unknown audience 'https://host/oauth/token'`)
      )
    })
    it('expired', () => {
      const customJwtBody = { ...jwtBody, iat: jwtBody.iat - 1200, exp: jwtBody.exp - 5000 }
      const jwt = JwtUtils.encode(rsaPrivateKey, jwtHeader, customJwtBody)
      expect(() => JwtUtils.decode(jwt, pubKeys, ['https://host/oauth/token'])).toThrow(
        new JwtVerifyError('Token has expired')
      )
    })
    it('always fail with expired', () => {
      const expiredPubKeys = {
        ...pubKeys,
        'test@expired.com': {
          '1@RS256': {
            publicKey: rsaPublicKey,
            validators: {
              exp: () => {
                throw new JwtVerifyError('Always expired')
              }
            }
          }
        }
      }
      const customJwtBody = { ...jwtBody }
      customJwtBody.iss = 'test@expired.com'
      const jwt = JwtUtils.encode(rsaPrivateKey, jwtHeader, customJwtBody)
      expect(() => JwtUtils.decode(jwt, expiredPubKeys, ['https://host/oauth/token'])).toThrow(
        new JwtVerifyError('Always expired')
      )
    })
    it('missing iss', () => {
      const customJwtBody = {
        aud: 'https://host/oauth/token',
        iat: unixNow,
        exp: unixNow + 600,
        scope: ['http://stuff', 'http://stuff2']
      }
      const jwt = JwtUtils.encode(rsaPrivateKey, jwtHeader, customJwtBody)
      expect(() => JwtUtils.decode(jwt, pubKeys, ['https://host/oauth/token'])).toThrow(
        new JwtVerifyError('No issuer set')
      )
    })
    it('iat invalid', () => {
      const customJwtBody = { ...jwtBody }
      customJwtBody.iat += 1200
      const jwt = JwtUtils.encode(rsaPrivateKey, jwtHeader, customJwtBody)
      expect(() => JwtUtils.decode(jwt, pubKeys, ['https://host/oauth/token'])).toThrow(
        new JwtVerifyError('Issued at in the future by more than 300 seconds')
      )
    })
    it('nbf invalid', () => {
      const customJwtBody = {
        ...jwtBody,
        nbf: jwtBody.iat + 1200
      }
      const jwt = JwtUtils.encode(rsaPrivateKey, jwtHeader, customJwtBody)
      expect(() => JwtUtils.decode(jwt, pubKeys, ['https://host/oauth/token'])).toThrow(
        new JwtVerifyError('Not before in the future by more than 300 seconds')
      )
    })
    it('unknown issuer', () => {
      const customJwtBody = { ...jwtBody }
      customJwtBody.iss = 'unknown@test.com'
      const jwt = JwtUtils.encode(rsaPrivateKey, jwtHeader, customJwtBody)
      expect(() => JwtUtils.decode(jwt, pubKeys, ['https://host/oauth/token'])).toThrow(
        new JwtVerifyError(`Unknown issuer 'unknown@test.com'`)
      )
    })
    it('wrong alg', () => {
      const customJwtHeader = { ...jwtHeader }
      customJwtHeader.alg = 'HS128'
      expect(() => JwtUtils.encode(rsaPrivateKey, customJwtHeader, jwtBody)).toThrow(
        new JwtVerifyError('Only alg RS256, RS384, RS512, ES256, ES384, ES512, HS256, HS384 and HS512 are supported')
      )
    })
    it('unknown kid', () => {
      const customJwtHeader = { ...jwtHeader }
      customJwtHeader.kid = '3'
      const jwt = JwtUtils.encode(rsaPrivateKey, customJwtHeader, jwtBody)
      expect(() => JwtUtils.decode(jwt, pubKeys, ['https://host/oauth/token'])).toThrow(
        new JwtVerifyError(`Unknown pubkey id '3' for this issuer`)
      )
    })
    it('invalid signature', () => {
      const customJwtHeader = { ...jwtHeader }
      customJwtHeader.kid = '2'
      const jwt = JwtUtils.encode(rsaPrivateKey, customJwtHeader, jwtBody)
      expect(() => JwtUtils.decode(jwt, pubKeys, ['https://host/oauth/token'])).toThrow(
        new JwtVerifyError(`Signature verification failed with alg 'RS256'`)
      )
    })
    it('invalid shared key', () => {
      const customJwtHeader = { ...jwtHeader }
      customJwtHeader.kid = '5'
      customJwtHeader.alg = 'HS256'
      const jwt = JwtUtils.encode('', customJwtHeader, jwtBody, 'sharedkey')
      expect(() => JwtUtils.decode(jwt, pubKeys, ['https://host/oauth/token'])).toThrow(
        new JwtVerifyError(`Verification failed with alg 'HS256'`)
      )
    })
    it('handle exception if its a JwtVerifyError', () => {
      const customJwtHeader = { ...jwtHeader }
      customJwtHeader.kid = '2'
      const jwt = JwtUtils.encode(rsaPrivateKey, customJwtHeader, jwtBody)
      try {
        JwtUtils.decode(jwt, pubKeys, ['https://host/oauth/token'])
      } catch (e) {
        if (e instanceof JwtVerifyError) {
          // Handled
        }
      }
    })
    it('invalid pubkey', () => {
      const customJwtHeader = { ...jwtHeader }
      customJwtHeader.kid = '4'
      const jwt = JwtUtils.encode(rsaPrivateKey, customJwtHeader, jwtBody)
      expect(() => JwtUtils.decode(jwt, pubKeys, ['https://host/oauth/token'])).toThrow()
    })
    it('success with broken token', () => {
      const expectedJwtBody = {
        id: 1,
        iat: 1519802691,
        exp: 1519802991,
        iss: 'test@test.com',
        aud: 'https://host/oauth/token'
      }

      const decodedJwtBody = JwtUtils.decode(
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwiaWF0IjoxNTE5ODAyNjkxfQ.p6t378Ri2JpOCm9WtC36ttyH8ILzG9-OWT_kgMrrRfo',
        pubKeys,
        ['https://host/oauth/token'],
        {
          fixup: (header: { kid: string }, body: { iss: string; aud: string; exp: number; iat: number }) => {
            header.kid = '2'
            body.iss = 'test@test.com'
            body.aud = 'https://host/oauth/token'
            body.exp = body.iat + 300
          },
          expiresSkew: 307584000
        } as Options
      )
      expect(decodedJwtBody).toEqual(expectedJwtBody)
    })
  })
})
