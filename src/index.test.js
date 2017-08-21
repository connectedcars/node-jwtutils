'use strict'

const expect = require('unexpected')
const jwtUtils = require('./index')
const JwtVerifyError = require('./jwtverifyerror')

const rsaPublicKey =
  '-----BEGIN PUBLIC KEY-----\n' +
  'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDdlatRjRjogo3WojgGHFHYLugd\n' +
  'UWAY9iR3fy4arWNA1KoS8kVw33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQs\n' +
  'HUfQrSDv+MuSUMAe8jzKE4qW+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1/xAK5D\n' +
  'o2kQ+X5xK9cipRgEKwIDAQAB\n' +
  '-----END PUBLIC KEY-----'

const rsaOtherPublicKey =
  '-----BEGIN PUBLIC KEY-----\n' +
  'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDf6PME6PIAF47/UzLDixmtlLvn\n' +
  'RkSGzixmdGJUurUZyz3B2ok5DIYYtdN1LWXmt0BRfA5B9SQAsZ4h9tdAs5zjVUe1\n' +
  's9oLHK0++UEM7vowvhqvMmxeVmcABtsx0IoXTryLLKcrdJQfmmeAItZAyYbz6Tzp\n' +
  'O6x06JSme6Xy0lOQawIDAQAB\n' +
  '-----END PUBLIC KEY-----'

const rsaPrivateKey =
  '-----BEGIN RSA PRIVATE KEY-----\n' +
  'MIICWwIBAAKBgQDdlatRjRjogo3WojgGHFHYLugdUWAY9iR3fy4arWNA1KoS8kVw\n' +
  '33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQsHUfQrSDv+MuSUMAe8jzKE4qW\n' +
  '+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1/xAK5Do2kQ+X5xK9cipRgEKwIDAQAB\n' +
  'AoGAD+onAtVye4ic7VR7V50DF9bOnwRwNXrARcDhq9LWNRrRGElESYYTQ6EbatXS\n' +
  '3MCyjjX2eMhu/aF5YhXBwkppwxg+EOmXeh+MzL7Zh284OuPbkglAaGhV9bb6/5Cp\n' +
  'uGb1esyPbYW+Ty2PC0GSZfIXkXs76jXAu9TOBvD0ybc2YlkCQQDywg2R/7t3Q2OE\n' +
  '2+yo382CLJdrlSLVROWKwb4tb2PjhY4XAwV8d1vy0RenxTB+K5Mu57uVSTHtrMK0\n' +
  'GAtFr833AkEA6avx20OHo61Yela/4k5kQDtjEf1N0LfI+BcWZtxsS3jDM3i1Hp0K\n' +
  'Su5rsCPb8acJo5RO26gGVrfAsDcIXKC+bQJAZZ2XIpsitLyPpuiMOvBbzPavd4gY\n' +
  '6Z8KWrfYzJoI/Q9FuBo6rKwl4BFoToD7WIUS+hpkagwWiz+6zLoX1dbOZwJACmH5\n' +
  'fSSjAkLRi54PKJ8TFUeOP15h9sQzydI8zJU+upvDEKZsZc/UhT/SySDOxQ4G/523\n' +
  'Y0sz/OZtSWcol/UMgQJALesy++GdvoIDLfJX5GBQpuFgFenRiRDabxrE9MNUZ2aP\n' +
  'FaFp+DyAe+b4nDwuJaW2LURbr8AEZga7oQj0uYxcYw==\n' +
  '-----END RSA PRIVATE KEY-----'

const ecPrivateKey =
  '-----BEGIN EC PRIVATE KEY-----\n' +
  'MHQCAQEEIEbBJ5shjRhQjmWZQfBu8t069BolPpmZjg+c2mSqr8BkoAcGBSuBBAAK\n' +
  'oUQDQgAEgYq9+AtlLZMXL2g61gwOG3vPQPeaWQD+3JcRUdcwdZm4duMXQZrwVBSr\n' +
  '5Kunr1NnK+0VCrcoUh09GFr8UTAq3g==\n' +
  '-----END EC PRIVATE KEY-----'

const ecPublicKey =
  '-----BEGIN PUBLIC KEY-----\n' +
  'MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEgYq9+AtlLZMXL2g61gwOG3vPQPeaWQD+\n' +
  '3JcRUdcwdZm4duMXQZrwVBSr5Kunr1NnK+0VCrcoUh09GFr8UTAq3g==\n' +
  '-----END PUBLIC KEY-----\n'

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
  }
}

describe('jwtUtils', () => {
  describe('encode/decode', () => {
    it('success with RSA at RS256, RS384 and RS512', () => {
      for (let algo of ['RS256', 'RS384', 'RS512']) {
        let customJwtHeader = Object.assign({}, jwtHeader)
        customJwtHeader.alg = algo
        let jwt = jwtUtils.encode(rsaPrivateKey, customJwtHeader, jwtBody)
        let decodedJwtBody = jwtUtils.decode(jwt, pubKeys, [
          'https://host/oauth/token'
        ])
        expect(jwtBody, 'to equal', decodedJwtBody)
      }
    })
    it('success with ECDSA at ES256, ES384 and ES512', () => {
      for (let algo of ['ES256', 'ES384', 'ES512']) {
        let customJwtHeader = Object.assign({}, jwtHeader)
        customJwtHeader.alg = algo
        let jwt = jwtUtils.encode(ecPrivateKey, customJwtHeader, jwtBody)
        let decodedJwtBody = jwtUtils.decode(jwt, pubKeys, [
          'https://host/oauth/token'
        ])
        expect(jwtBody, 'to equal', decodedJwtBody)
      }
    })
    it('success without kid', () => {
      let customJwtHeader = Object.assign({}, jwtHeader)
      delete customJwtHeader.kid
      let jwt = jwtUtils.encode(rsaPrivateKey, customJwtHeader, jwtBody)
      let decodedJwtBody = jwtUtils.decode(jwt, pubKeys, [
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
      let jwt = jwtUtils.encode(rsaPrivateKey, jwtHeader, customJwtBody)
      let decodedJwtBody = jwtUtils.decode(jwt, pubKeys, [
        'https://host/oauth/token'
      ])
      expect(customJwtBody, 'to equal', decodedJwtBody)
    })
    it('unknown aud', () => {
      let jwt = jwtUtils.encode(rsaPrivateKey, jwtHeader, jwtBody)
      expect(
        () => {
          jwtUtils.decode(jwt, pubKeys, ['https://myhost/oauth/token'])
        },
        'to throw',
        'Unknown audience'
      )
    })
    it('expired', () => {
      let customJwtBody = Object.assign({}, jwtBody)
      customJwtBody.iat -= 1200
      customJwtBody.exp -= 800
      let jwt = jwtUtils.encode(rsaPrivateKey, jwtHeader, customJwtBody)
      expect(
        () => {
          jwtUtils.decode(jwt, pubKeys, ['https://host/oauth/token'])
        },
        'to throw',
        'Token has expired'
      )
    })
    it('missing exp', () => {
      let customJwtBody = Object.assign({}, jwtBody)
      delete customJwtBody.exp
      let jwt = jwtUtils.encode(rsaPrivateKey, jwtHeader, customJwtBody)
      expect(
        () => {
          jwtUtils.decode(jwt, pubKeys, ['https://host/oauth/token'])
        },
        'to throw',
        'No expires set on token'
      )
    })
    it('missing iss', () => {
      let customJwtBody = Object.assign({}, jwtBody)
      delete customJwtBody.iss
      let jwt = jwtUtils.encode(rsaPrivateKey, jwtHeader, customJwtBody)
      expect(
        () => {
          jwtUtils.decode(jwt, pubKeys, ['https://host/oauth/token'])
        },
        'to throw',
        'No issuer set'
      )
    })
    it('iat invalid', () => {
      let customJwtBody = Object.assign({}, jwtBody)
      customJwtBody.iat += 1200
      let jwt = jwtUtils.encode(rsaPrivateKey, jwtHeader, customJwtBody)
      expect(
        () => {
          jwtUtils.decode(jwt, pubKeys, ['https://host/oauth/token'])
        },
        'to throw',
        'Issued at in the future by more than 300 seconds'
      )
    })
    it('nbf invalid', () => {
      let customJwtBody = Object.assign({}, jwtBody)
      customJwtBody.nbf = customJwtBody.iat + 1200
      let jwt = jwtUtils.encode(rsaPrivateKey, jwtHeader, customJwtBody)
      expect(
        () => {
          jwtUtils.decode(jwt, pubKeys, ['https://host/oauth/token'])
        },
        'to throw',
        'Not before in the future by more than 300 seconds'
      )
    })
    it('unknown issuer', () => {
      let customJwtBody = Object.assign({}, jwtBody)
      customJwtBody.iss += 'unknown@test.com'
      let jwt = jwtUtils.encode(rsaPrivateKey, jwtHeader, customJwtBody)
      expect(
        () => {
          jwtUtils.decode(jwt, pubKeys, ['https://host/oauth/token'])
        },
        'to throw',
        'Unknown issuer'
      )
    })
    it('wrong alg', () => {
      let customJwtHeader = Object.assign({}, jwtHeader)
      customJwtHeader.alg = 'HS256'
      expect(
        () => {
          jwtUtils.encode(rsaPrivateKey, customJwtHeader, jwtBody)
        },
        'to throw',
        'Only alg RS256, RS384, RS512, ES256, ES384 and ES512 are supported'
      )
    })
    it('unknown kid', () => {
      let customJwtHeader = Object.assign({}, jwtHeader)
      customJwtHeader.kid = 3
      let jwt = jwtUtils.encode(rsaPrivateKey, customJwtHeader, jwtBody)
      expect(
        () => {
          jwtUtils.decode(jwt, pubKeys, ['https://host/oauth/token'])
        },
        'to throw',
        'Unknown pubkey id for this issuer'
      )
    })
    it('invalid signature', () => {
      let customJwtHeader = Object.assign({}, jwtHeader)
      customJwtHeader.kid = 2
      let jwt = jwtUtils.encode(rsaPrivateKey, customJwtHeader, jwtBody)
      expect(
        () => {
          jwtUtils.decode(jwt, pubKeys, ['https://host/oauth/token'])
        },
        'to throw',
        'Signature verification failed with alg RS256'
      )
    })
    it('Handle exception if its a JwtVerifyError', () => {
      let customJwtHeader = Object.assign({}, jwtHeader)
      customJwtHeader.kid = 2
      let jwt = jwtUtils.encode(rsaPrivateKey, customJwtHeader, jwtBody)
      try {
        jwtUtils.decode(jwt, pubKeys, ['https://host/oauth/token'])
      } catch (e) {
        if (e instanceof JwtVerifyError) {
          // Handled
        }
      }
    })
    it('invalid pubkey', () => {
      let customJwtHeader = Object.assign({}, jwtHeader)
      customJwtHeader.kid = 4
      let jwt = jwtUtils.encode(rsaPrivateKey, customJwtHeader, jwtBody)
      expect(
        () => {
          jwtUtils.decode(jwt, pubKeys, ['https://host/oauth/token'])
        },
        'to throw',
        'PEM_read_bio_PUBKEY failed'
      )
    })
  })
})
