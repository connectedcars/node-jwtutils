// @ts-check
'use strict'

const expect = require('unexpected')
const {
  rsaPrivateKey,
  rsaPublicKey,
  ecPrivateKey,
  ecPublicKey,
  rsaOtherPublicKey
} = require('./testresources')

const { JwtUtils, JwtVerifyError } = require('./index')
const oldJwtUtils = require('./index')

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

const pubKeys = {
  'test@test.com': {
    'default@RS256': rsaPublicKey,
    '1@RS256': rsaPublicKey,
    '1@RS384': rsaPublicKey,
    '1@RS512': rsaPublicKey,
    '1@ES256': ecPublicKey,
    '1@ES384': ecPublicKey,
    '1@ES512': ecPublicKey,
    '2@RS256': rsaOtherPublicKey,
    '3@RS256': null,
    '4@RS256': rsaOtherPublicKey.substr(2)
  },
  'test@custom.com': {
    '1@RS256': {
      publicKey: rsaPublicKey,
      expiresSkew: 600,
      expiresMax: 86400
    }
  },
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

describe('jwtUtils', () => {
  describe('encode/decode', () => {
    it('success old inteface', () => {
      let jwt = oldJwtUtils.encode(rsaPrivateKey, jwtHeader, jwtBody)
      let decodedJwtBody = oldJwtUtils.decode(
        jwt,
        pubKeys,
        ['https://host/oauth/token'],
        300
      )
      expect(jwtBody, 'to equal', decodedJwtBody)
    })
    it('success with RSA at RS256, RS384 and RS512', () => {
      for (let algo of ['RS256', 'RS384', 'RS512']) {
        let customJwtHeader = Object.assign({}, jwtHeader)
        customJwtHeader.alg = algo
        let jwt = JwtUtils.encode(rsaPrivateKey, customJwtHeader, jwtBody)
        let decodedJwtBody = JwtUtils.decode(jwt, pubKeys, [
          'https://host/oauth/token'
        ])
        expect(jwtBody, 'to equal', decodedJwtBody)
      }
    })
    it('success with ECDSA at ES256, ES384 and ES512', () => {
      for (let algo of ['ES256', 'ES384', 'ES512']) {
        let customJwtHeader = Object.assign({}, jwtHeader)
        customJwtHeader.alg = algo
        let jwt = JwtUtils.encode(ecPrivateKey, customJwtHeader, jwtBody)
        let decodedJwtBody = JwtUtils.decode(jwt, pubKeys, [
          'https://host/oauth/token'
        ])
        expect(jwtBody, 'to equal', decodedJwtBody)
      }
    })
    it('success without kid', () => {
      let customJwtHeader = Object.assign({}, jwtHeader)
      delete customJwtHeader.kid
      let jwt = JwtUtils.encode(rsaPrivateKey, customJwtHeader, jwtBody)
      let decodedJwtBody = JwtUtils.decode(jwt, pubKeys, [
        'https://host/oauth/token'
      ])
      expect(jwtBody, 'to equal', decodedJwtBody)
    })
    it('success with array aud', () => {
      let customJwtBody = Object.assign({}, jwtBody)
      customJwtBody.aud = [
        'https://myhost/oauth/token',
        'https://host/oauth/token'
      ]
      let jwt = JwtUtils.encode(rsaPrivateKey, jwtHeader, customJwtBody)
      let decodedJwtBody = JwtUtils.decode(jwt, pubKeys, [
        'https://host/oauth/token'
      ])
      expect(customJwtBody, 'to equal', decodedJwtBody)
    })
    it('success with expired token', () => {
      let customJwtBody = Object.assign({}, jwtBody)
      customJwtBody.iss = 'test@custom.com'
      customJwtBody.exp -= 600
      let jwt = JwtUtils.encode(rsaPrivateKey, jwtHeader, customJwtBody)
      let decodedJwtBody = JwtUtils.decode(jwt, pubKeys, [
        'https://host/oauth/token'
      ])
      expect(customJwtBody, 'to equal', decodedJwtBody)
    })
    it('token outside maximum expires', () => {
      let customJwtBody = Object.assign({}, jwtBody)
      customJwtBody.iss = 'test@custom.com'
      customJwtBody.exp += 172800
      let jwt = JwtUtils.encode(rsaPrivateKey, jwtHeader, customJwtBody)
      expect(
        () => {
          JwtUtils.decode(jwt, pubKeys, ['https://host/oauth/token'])
        },
        'to throw',
        `Expires in the future by more than 86400 seconds`
      )
    })
    it('always fail with expired', () => {
      let customJwtBody = Object.assign({}, jwtBody)
      customJwtBody.iss = 'test@expired.com'
      let jwt = JwtUtils.encode(rsaPrivateKey, jwtHeader, customJwtBody)
      expect(
        () => {
          JwtUtils.decode(jwt, pubKeys, ['https://host/oauth/token'])
        },
        'to throw',
        `Always expired`
      )
    })
    it('token outside maximum expires using decode options', () => {
      let customJwtBody = Object.assign({}, jwtBody)
      customJwtBody.exp += 172800
      let jwt = JwtUtils.encode(rsaPrivateKey, jwtHeader, customJwtBody)
      expect(
        () => {
          JwtUtils.decode(jwt, pubKeys, ['https://host/oauth/token'], {
            expiresMax: 600
          })
        },
        'to throw',
        `Expires in the future by more than 600 seconds`
      )
    })
    it('token outside maximum expires using nbf', () => {
      let customJwtBody = Object.assign({}, jwtBody)
      customJwtBody.exp += 172800
      customJwtBody.nbf = customJwtBody.iat
      delete customJwtBody.iat
      let jwt = JwtUtils.encode(rsaPrivateKey, jwtHeader, customJwtBody)
      expect(
        () => {
          JwtUtils.decode(jwt, pubKeys, ['https://host/oauth/token'], {
            expiresMax: 600
          })
        },
        'to throw',
        `Expires in the future by more than 600 seconds`
      )
    })
    it('token outside maximum expires using unixNow', () => {
      let customJwtBody = Object.assign({}, jwtBody)
      customJwtBody.exp += 172800
      delete customJwtBody.iat
      let jwt = JwtUtils.encode(rsaPrivateKey, jwtHeader, customJwtBody)
      expect(
        () => {
          JwtUtils.decode(jwt, pubKeys, ['https://host/oauth/token'], {
            expiresMax: 600
          })
        },
        'to throw',
        `Expires in the future by more than 600 seconds`
      )
    })
    it('unknown aud', () => {
      let jwt = JwtUtils.encode(rsaPrivateKey, jwtHeader, jwtBody)
      expect(
        () => {
          JwtUtils.decode(jwt, pubKeys, ['https://myhost/oauth/token'])
        },
        'to throw',
        `Unknown audience 'https://host/oauth/token'`
      )
    })
    it('expired', () => {
      let customJwtBody = Object.assign({}, jwtBody)
      customJwtBody.iat -= 1200
      customJwtBody.exp -= 800
      let jwt = JwtUtils.encode(rsaPrivateKey, jwtHeader, customJwtBody)
      expect(
        () => {
          JwtUtils.decode(jwt, pubKeys, ['https://host/oauth/token'])
        },
        'to throw',
        'Token has expired'
      )
    })
    it('missing exp', () => {
      let customJwtBody = Object.assign({}, jwtBody)
      delete customJwtBody.exp
      let jwt = JwtUtils.encode(rsaPrivateKey, jwtHeader, customJwtBody)
      expect(
        () => {
          JwtUtils.decode(jwt, pubKeys, ['https://host/oauth/token'])
        },
        'to throw',
        'No expires set on token'
      )
    })
    it('missing iss', () => {
      let customJwtBody = Object.assign({}, jwtBody)
      delete customJwtBody.iss
      let jwt = JwtUtils.encode(rsaPrivateKey, jwtHeader, customJwtBody)
      expect(
        () => {
          JwtUtils.decode(jwt, pubKeys, ['https://host/oauth/token'])
        },
        'to throw',
        'No issuer set'
      )
    })
    it('iat invalid', () => {
      let customJwtBody = Object.assign({}, jwtBody)
      customJwtBody.iat += 1200
      let jwt = JwtUtils.encode(rsaPrivateKey, jwtHeader, customJwtBody)
      expect(
        () => {
          JwtUtils.decode(jwt, pubKeys, ['https://host/oauth/token'])
        },
        'to throw',
        'Issued at in the future by more than 300 seconds'
      )
    })
    it('nbf invalid', () => {
      let customJwtBody = Object.assign({}, jwtBody)
      customJwtBody.nbf = customJwtBody.iat + 1200
      let jwt = JwtUtils.encode(rsaPrivateKey, jwtHeader, customJwtBody)
      expect(
        () => {
          JwtUtils.decode(jwt, pubKeys, ['https://host/oauth/token'])
        },
        'to throw',
        'Not before in the future by more than 300 seconds'
      )
    })
    it('unknown issuer', () => {
      let customJwtBody = Object.assign({}, jwtBody)
      customJwtBody.iss = 'unknown@test.com'
      let jwt = JwtUtils.encode(rsaPrivateKey, jwtHeader, customJwtBody)
      expect(
        () => {
          JwtUtils.decode(jwt, pubKeys, ['https://host/oauth/token'])
        },
        'to throw',
        `Unknown issuer 'unknown@test.com'`
      )
    })
    it('wrong alg', () => {
      let customJwtHeader = Object.assign({}, jwtHeader)
      customJwtHeader.alg = 'HS256'
      expect(
        () => {
          JwtUtils.encode(rsaPrivateKey, customJwtHeader, jwtBody)
        },
        'to throw',
        'Only alg RS256, RS384, RS512, ES256, ES384 and ES512 are supported'
      )
    })
    it('unknown kid', () => {
      let customJwtHeader = Object.assign({}, jwtHeader)
      customJwtHeader.kid = '3'
      let jwt = JwtUtils.encode(rsaPrivateKey, customJwtHeader, jwtBody)
      expect(
        () => {
          JwtUtils.decode(jwt, pubKeys, ['https://host/oauth/token'])
        },
        'to throw',
        `Unknown pubkey id '3' for this issuer`
      )
    })
    it('invalid signature', () => {
      let customJwtHeader = Object.assign({}, jwtHeader)
      customJwtHeader.kid = '2'
      let jwt = JwtUtils.encode(rsaPrivateKey, customJwtHeader, jwtBody)
      expect(
        () => {
          JwtUtils.decode(jwt, pubKeys, ['https://host/oauth/token'])
        },
        'to throw',
        `Signature verification failed with alg 'RS256'`
      )
    })
    it('Handle exception if its a JwtVerifyError', () => {
      let customJwtHeader = Object.assign({}, jwtHeader)
      customJwtHeader.kid = '2'
      let jwt = JwtUtils.encode(rsaPrivateKey, customJwtHeader, jwtBody)
      try {
        JwtUtils.decode(jwt, pubKeys, ['https://host/oauth/token'])
      } catch (e) {
        if (e instanceof JwtVerifyError) {
          // Handled
        }
      }
    })
    it('invalid pubkey', () => {
      let customJwtHeader = Object.assign({}, jwtHeader)
      customJwtHeader.kid = '4'
      let jwt = JwtUtils.encode(rsaPrivateKey, customJwtHeader, jwtBody)
      expect(
        () => {
          JwtUtils.decode(jwt, pubKeys, ['https://host/oauth/token'])
        },
        'to throw a',
        Error
      )
    })
  })
})
