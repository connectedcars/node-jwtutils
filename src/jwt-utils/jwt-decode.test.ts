import { JwtVerifyError } from '../jwt-verify-error'
import type { PublicKeys } from '../pubkeys-helper'
import type { DecodingOptions } from './jwt-decode'
import { decode } from './jwt-decode'

const audiences: string[] = []

const publicKey =
  '-----BEGIN PUBLIC KEY-----\n' +
  'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDdlatRjRjogo3WojgGHFHYLugd\n' +
  'UWAY9iR3fy4arWNA1KoS8kVw33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQs\n' +
  'HUfQrSDv+MuSUMAe8jzKE4qW+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1/xAK5D\n' +
  'o2kQ+X5xK9cipRgEKwIDAQAB\n' +
  '-----END PUBLIC KEY-----'

const pubKeys: PublicKeys = {
  'test@test.com': {
    '1@RS256': publicKey,
    'default@RS256': publicKey
  }
}

const defaultOptions: DecodingOptions = {
  expiresSkew: 0,
  expiresMax: 0,
  nbfIatSkew: 300,
  validators: {
    aud: () => true,
    exp: () => true
  }
}

const testJwt =
  'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ.eyJhdWQiOiJodHRwczovL2hvc3Qvb2F1dGgvdG9rZW4iLCJpc3MiOiJ0ZXN0QHRlc3QuY29tIiwiaWF0IjoxNTAzMzM1MTY5LCJleHAiOjE1MDMzMzU3NjksInNjb3BlIjpbImh0dHA6Ly9zdHVmZiIsImh0dHA6Ly9zdHVmZjIiXX0.zO278VV6NzwsvBrAIc15mOfwza-FkmLCV28NRXnrI550xw1S1145cS1UsZP5zXxcrk5f4oEgB91Jt6ble76yK5nU68fALUXtfe7xPUkhcOUIw92q_x_Iaaw4z6a71NtyishCfJlbmwkXXEq5YCVAvX3KNDtyPf_fQrAqjzsbgQc'

const testJwtInvalidHeader =
  'eyJ0eXAiOiJKV1QiLCJhbGciOnRydWUsImtpZCI6IjEifQo.eyJhdWQiOiJodHRwczovL2hvc3Qvb2F1dGgvdG9rZW4iLCJpc3MiOiJ0ZXN0QHRlc3QuY29tIiwiaWF0IjoxNTAzMzM1MTY5LCJleHAiOjE1MDMzMzU3NjksInNjb3BlIjpbImh0dHA6Ly9zdHVmZiIsImh0dHA6Ly9zdHVmZjIiXX0.zO278VV6NzwsvBrAIc15mOfwza-FkmLCV28NRXnrI550xw1S1145cS1UsZP5zXxcrk5f4oEgB91Jt6ble76yK5nU68fALUXtfe7xPUkhcOUIw92q_x_Iaaw4z6a71NtyishCfJlbmwkXXEq5YCVAvX3KNDtyPf_fQrAqjzsbgQc'

const testJwtInvalidBodyIatIsString =
  'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ.eyJhdWQiOiJodHRwczovL2hvc3Qvb2F1dGgvdG9rZW4iLCJpc3MiOiJ0ZXN0QHRlc3QuY29tIiwiaWF0Ijoib2siLCJleHAiOjE1MDMzMzU3NjksInNjb3BlIjpbImh0dHA6Ly9zdHVmZiIsImh0dHA6Ly9zdHVmZjIiXX0K.zO278VV6NzwsvBrAIc15mOfwza-FkmLCV28NRXnrI550xw1S1145cS1UsZP5zXxcrk5f4oEgB91Jt6ble76yK5nU68fALUXtfe7xPUkhcOUIw92q_x_Iaaw4z6a71NtyishCfJlbmwkXXEq5YCVAvX3KNDtyPf_fQrAqjzsbgQc'

const testJwtInvalidBodyAudienceArrayOfNumbers =
  'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ.eyJhdWQiOlsxLDJdLCJpc3MiOiJ0ZXN0QHRlc3QuY29tIiwiaWF0Ijoib2siLCJleHAiOjE1MDMzMzU3NjksInNjb3BlIjpbImh0dHA6Ly9zdHVmZiIsImh0dHA6Ly9zdHVmZjIiXX0K.zO278VV6NzwsvBrAIc15mOfwza-FkmLCV28NRXnrI550xw1S1145cS1UsZP5zXxcrk5f4oEgB91Jt6ble76yK5nU68fALUXtfe7xPUkhcOUIw92q_x_Iaaw4z6a71NtyishCfJlbmwkXXEq5YCVAvX3KNDtyPf_fQrAqjzsbgQc'

const testJwtWrongAlg =
  'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzEyOCJ9.eyJhdWQiOiJodHRwczovL2hvc3Qvb2F1dGgvdG9rZW4iLCJpc3MiOiJ0ZXN0QHRlc3QuY29tIiwiaWF0IjoxNTAzMzM2NzU5LCJleHAiOjE1MDMzMzczNTksInNjb3BlIjpbImh0dHA6Ly9zdHVmZiIsImh0dHA6Ly9zdHVmZjIiXX0.12co2gXwBxmZ2uLJecd26bfteCLBx7jgu_9rp2hhKAHWA4qFKm1HcQOZXqDvHkjflQDtNAQ1ZUUf3U8kntUUAmMOjhHx0BspC-xuaTFylZWqj--A2_w9e7JSk46TF_x3e_hZLB3rtyuSEAPMh_nOCsmM-4A2fnQx0Y5p-Bwbt0I'

describe('jwt-decode', () => {
  describe('decode', () => {
    it('decodes', () => {
      expect(decode(testJwt, pubKeys, audiences, defaultOptions)).toEqual({
        aud: 'https://host/oauth/token',
        exp: 1503335769,
        iat: 1503335169,
        iss: 'test@test.com',
        scope: ['http://stuff', 'http://stuff2']
      })
    })

    it('checks for amount of dots', () => {
      expect(() => decode('hello.test', pubKeys, audiences)).toThrow(new JwtVerifyError('JWT does not contain 3 dots'))
    })

    it('checks for a valid header', async () => {
      expect(() => decode(testJwtInvalidHeader, pubKeys, audiences)).toThrow(new JwtVerifyError('Invalid header'))
    })

    it('checks for invalid body', () => {
      expect(() => decode(testJwtInvalidBodyIatIsString, pubKeys, audiences)).toThrow(
        new JwtVerifyError('Invalid body')
      )

      expect(() => decode(testJwtInvalidBodyAudienceArrayOfNumbers, pubKeys, audiences)).toThrow(
        new JwtVerifyError('Invalid body')
      )
    })

    it('checks for a valid header after fixup', async () => {
      expect(() =>
        decode(testJwtInvalidHeader, pubKeys, audiences, {
          fixup: header => {
            // @ts-expect-error Type 'boolean' is not assignable to type 'string'
            header.alg = true
          }
        })
      ).toThrow(new JwtVerifyError('Invalid header'))
    })

    it('checks for invalid body after fixup', () => {
      expect(() =>
        decode(testJwtInvalidBodyIatIsString, pubKeys, audiences, {
          fixup: (_header, body) => {
            // @ts-expect-error Type 'boolean' is not assignable to type 'string'
            body.jti = true
          }
        })
      ).toThrow(new JwtVerifyError('Invalid body'))
    })

    it('checks for invalid json', () => {
      expect(() => decode(testJwt.substring(10), pubKeys, audiences)).toThrow(/^Unexpected token '\$'/)
    })

    it('checks for wrong alg', () => {
      expect(() => decode(testJwtWrongAlg, pubKeys, audiences)).toThrow(
        new JwtVerifyError('Only alg RS256, RS384, RS512, ES256, ES384, ES512, HS256, HS384 and HS512 are supported')
      )
    })
  })
})
