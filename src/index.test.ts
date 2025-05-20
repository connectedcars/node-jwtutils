import { jwtUtils, JwtVerifyError, type PublicKeys } from './index'
import type { DecodingOptions, ValidatorOptions } from './jwt-utils/decode-validators'
import { ecPrivateKey, ecPublicKey, rsaOtherPublicKey, rsaPrivateKey, rsaPublicKey } from './test/test-resources'
import type { JwtBody, JwtHeader } from './types'

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

const pubKeys: PublicKeys = {
  'test@test.com': {
    'default@RS256': rsaPublicKey,
    '1@RS256': rsaPublicKey,
    '1@RS384': rsaPublicKey,
    '1@RS512': rsaPublicKey,
    '1@ES256': ecPublicKey,
    '1@ES384': ecPublicKey,
    '1@ES512': ecPublicKey,
    '2@RS256': rsaOtherPublicKey,
    '4@RS256': rsaOtherPublicKey.substring(2),
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

describe('index', () => {
  describe('encode/decode', () => {
    it('success with RSA at RS256, RS384 and RS512', () => {
      for (const algo of ['RS256', 'RS384', 'RS512']) {
        const customJwtHeader = { ...jwtHeader }
        customJwtHeader.alg = algo

        const jwt = jwtUtils.encode(rsaPrivateKey, customJwtHeader, jwtBody)
        const decodedJwtBody = jwtUtils.decode(jwt, pubKeys, ['https://host/oauth/token'])

        expect(jwtBody).toEqual(decodedJwtBody)
      }
    })

    it('success with ECDSA at ES256, ES384 and ES512', () => {
      for (const algo of ['ES256', 'ES384', 'ES512']) {
        const customJwtHeader = { ...jwtHeader }
        customJwtHeader.alg = algo

        const jwt = jwtUtils.encode(ecPrivateKey, customJwtHeader, jwtBody)
        const decodedJwtBody = jwtUtils.decode(jwt, pubKeys, ['https://host/oauth/token'])

        expect(jwtBody).toEqual(decodedJwtBody)
      }
    })

    it('success with HS256, HS384 and HS512', () => {
      for (const algo of ['HS256', 'HS384', 'HS512']) {
        const customJwtHeader = { ...jwtHeader } as JwtHeader
        customJwtHeader.kid = '2'
        customJwtHeader.alg = algo

        const jwt = jwtUtils.encode('', customJwtHeader, jwtBody, 'sharedkey')
        const decodedJwtBody = jwtUtils.decode(jwt, pubKeys, ['https://host/oauth/token'])

        expect(jwtBody).toEqual(decodedJwtBody)
      }
    })

    it('success without kid', () => {
      const customJwtHeader = { typ: jwtHeader.typ, alg: jwtHeader.alg } as JwtHeader
      const jwt = jwtUtils.encode(rsaPrivateKey, customJwtHeader, jwtBody)
      const decodedJwtBody = jwtUtils.decode(jwt, pubKeys, ['https://host/oauth/token'])

      expect(jwtBody).toEqual(decodedJwtBody)
    })

    it('success with array aud', () => {
      const customJwtBody: JwtBody = {
        ...jwtBody,
        aud: ['https://myhost/oauth/token', 'https://host/oauth/token']
      }
      const jwt = jwtUtils.encode(rsaPrivateKey, jwtHeader, customJwtBody)
      const decodedJwtBody = jwtUtils.decode(jwt, pubKeys, ['https://host/oauth/token'])

      expect(customJwtBody).toEqual(decodedJwtBody)
    })

    it('success with expired token', () => {
      const customJwtBody = { ...jwtBody }
      customJwtBody.iss = 'test@custom.com'
      customJwtBody.exp! -= 600

      const jwt = jwtUtils.encode(rsaPrivateKey, jwtHeader, customJwtBody)
      const decodedJwtBody = jwtUtils.decode(jwt, pubKeys, ['https://host/oauth/token'])

      expect(customJwtBody).toEqual(decodedJwtBody)
    })

    it('token outside maximum expires', () => {
      const customJwtBody = { ...jwtBody }
      customJwtBody.iss = 'test@custom.com'
      customJwtBody.exp! += 172800

      const jwt = jwtUtils.encode(rsaPrivateKey, jwtHeader, customJwtBody)

      expect(() => jwtUtils.decode(jwt, pubKeys, ['https://host/oauth/token'])).toThrow(
        new JwtVerifyError('Expires in the future by more than 86400 seconds')
      )
    })

    it('token outside maximum expires using decode options', () => {
      const customJwtBody = { ...jwtBody }
      customJwtBody.exp! += 172800

      const jwt = jwtUtils.encode(rsaPrivateKey, jwtHeader, customJwtBody)

      expect(() =>
        jwtUtils.decode(jwt, pubKeys, ['https://host/oauth/token'], {
          expiresMax: 600
        } as DecodingOptions)
      ).toThrow(new JwtVerifyError('Expires in the future by more than 600 seconds'))
    })

    it('token outside maximum expires using nbf', () => {
      const customJwtBody = { ...jwtBody, exp: jwtBody.exp! + 172800, nbf: jwtBody.iat }
      const jwt = jwtUtils.encode(rsaPrivateKey, jwtHeader, customJwtBody)

      expect(() =>
        jwtUtils.decode(jwt, pubKeys, ['https://host/oauth/token'], {
          expiresMax: 600
        } as DecodingOptions)
      ).toThrow(new JwtVerifyError('Expires in the future by more than 600 seconds'))
    })

    it('token outside maximum expires using unixNow', () => {
      const customJwtBody = { ...jwtBody, exp: jwtBody.exp! + 172800 }
      const jwt = jwtUtils.encode(rsaPrivateKey, jwtHeader, customJwtBody)

      expect(() =>
        jwtUtils.decode(jwt, pubKeys, ['https://host/oauth/token'], {
          expiresMax: 600
        } as DecodingOptions)
      ).toThrow(new JwtVerifyError('Expires in the future by more than 600 seconds'))
    })

    it('unknown aud', () => {
      const jwt = jwtUtils.encode(rsaPrivateKey, jwtHeader, jwtBody)

      expect(() => jwtUtils.decode(jwt, pubKeys, ['https://myhost/oauth/token'])).toThrow(
        new JwtVerifyError(`Unknown audience 'https://host/oauth/token'`)
      )
    })

    it('expired', () => {
      const customJwtBody = { ...jwtBody, iat: jwtBody.iat! - 1200, exp: jwtBody.exp! - 5000 }
      const jwt = jwtUtils.encode(rsaPrivateKey, jwtHeader, customJwtBody)

      expect(() => jwtUtils.decode(jwt, pubKeys, ['https://host/oauth/token'])).toThrow(
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
              // eslint-disable-next-line @typescript-eslint/no-unused-vars
              exp: (_body: JwtBody, _unixNow: number, _options: ValidatorOptions) => {
                throw new JwtVerifyError('Always expired')
              }
            }
          }
        }
      }
      const customJwtBody = { ...jwtBody }
      customJwtBody.iss = 'test@expired.com'
      const jwt = jwtUtils.encode(rsaPrivateKey, jwtHeader, customJwtBody)

      expect(() => jwtUtils.decode(jwt, expiredPubKeys, ['https://host/oauth/token'])).toThrow(
        new JwtVerifyError('Always expired')
      )
    })

    it('missing iss', () => {
      const customJwtBody: JwtBody = {
        aud: 'https://host/oauth/token',
        iat: unixNow,
        exp: unixNow + 600,
        scope: ['http://stuff', 'http://stuff2']
      }

      const jwt = jwtUtils.encode(rsaPrivateKey, jwtHeader, customJwtBody)

      expect(() => jwtUtils.decode(jwt, pubKeys, ['https://host/oauth/token'])).toThrow(
        new JwtVerifyError('No issuer set')
      )
    })

    it('iat invalid', () => {
      const customJwtBody = { ...jwtBody }
      customJwtBody.iat! += 1200

      const jwt = jwtUtils.encode(rsaPrivateKey, jwtHeader, customJwtBody)

      expect(() => jwtUtils.decode(jwt, pubKeys, ['https://host/oauth/token'])).toThrow(
        new JwtVerifyError('Issued at in the future by more than 300 seconds')
      )
    })

    it('nbf invalid', () => {
      const customJwtBody = {
        ...jwtBody,
        nbf: jwtBody.iat! + 1200
      }
      const jwt = jwtUtils.encode(rsaPrivateKey, jwtHeader, customJwtBody)

      expect(() => jwtUtils.decode(jwt, pubKeys, ['https://host/oauth/token'])).toThrow(
        new JwtVerifyError('Not before in the future by more than 300 seconds')
      )
    })

    it('unknown issuer', () => {
      const customJwtBody = { ...jwtBody }
      customJwtBody.iss = 'unknown@test.com'

      const jwt = jwtUtils.encode(rsaPrivateKey, jwtHeader, customJwtBody)

      expect(() => jwtUtils.decode(jwt, pubKeys, ['https://host/oauth/token'])).toThrow(
        new JwtVerifyError(`Unknown issuer 'unknown@test.com'`)
      )
    })

    it('unknown kid', () => {
      const customJwtHeader = { ...jwtHeader }
      customJwtHeader.kid = '3'

      const jwt = jwtUtils.encode(rsaPrivateKey, customJwtHeader, jwtBody)

      expect(() => jwtUtils.decode(jwt, pubKeys, ['https://host/oauth/token'])).toThrow(
        new JwtVerifyError(`Unknown pubkey id '3' for this issuer`)
      )
    })

    it('invalid signature', () => {
      const customJwtHeader = { ...jwtHeader }
      customJwtHeader.kid = '2'

      const jwt = jwtUtils.encode(rsaPrivateKey, customJwtHeader, jwtBody)

      expect(() => jwtUtils.decode(jwt, pubKeys, ['https://host/oauth/token'])).toThrow(
        new JwtVerifyError(`Signature verification failed with algorithm 'RS256'`)
      )
    })

    it('invalid shared key', () => {
      const customJwtHeader = { ...jwtHeader }
      customJwtHeader.kid = '5'
      customJwtHeader.alg = 'HS256'

      const jwt = jwtUtils.encode('', customJwtHeader, jwtBody, 'sharedkey')

      expect(() => jwtUtils.decode(jwt, pubKeys, ['https://host/oauth/token'])).toThrow(
        new JwtVerifyError(`Verification failed with algorithm 'HS256'`)
      )
    })

    it('handle exception if its a JwtVerifyError', () => {
      const customJwtHeader = { ...jwtHeader }
      customJwtHeader.kid = '2'

      const jwt = jwtUtils.encode(rsaPrivateKey, customJwtHeader, jwtBody)

      expect(() => jwtUtils.decode(jwt, pubKeys, ['https://host/oauth/token'])).toThrow(JwtVerifyError)
    })

    it('invalid pubkey', () => {
      const customJwtHeader = { ...jwtHeader }
      customJwtHeader.kid = '4'

      const jwt = jwtUtils.encode(rsaPrivateKey, customJwtHeader, jwtBody)

      expect(() => jwtUtils.decode(jwt, pubKeys, ['https://host/oauth/token'])).toThrow()
    })

    it('success with broken token', () => {
      const expectedJwtBody = {
        id: 1,
        iat: 1519802691,
        exp: 1519802991,
        iss: 'test@test.com',
        aud: 'https://host/oauth/token'
      }

      const decodedJwtBody = jwtUtils.decode(
        'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwiaWF0IjoxNTE5ODAyNjkxfQ.p6t378Ri2JpOCm9WtC36ttyH8ILzG9-OWT_kgMrrRfo',
        pubKeys,
        ['https://host/oauth/token'],
        {
          fixup: (header: JwtHeader, body: JwtBody) => {
            header.kid = '2'
            body.iss = 'test@test.com'
            body.aud = 'https://host/oauth/token'
            body.exp = body.iat! + 300
          },
          expiresSkew: 307584000
        }
      )

      expect(decodedJwtBody).toEqual(expectedJwtBody)
    })
  })
})
