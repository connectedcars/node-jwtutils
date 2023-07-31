import { JwtServiceAuthError } from './jwtserviceautherror'
import * as JwtUtils from './jwtdecode'
import {JwtVerifyError} from './jwtverifyerror'
import { rsaPublicKey } from './testresources'

const audiences = []

const publicKey =
  '-----BEGIN PUBLIC KEY-----\n' +
  'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDdlatRjRjogo3WojgGHFHYLugd\n' +
  'UWAY9iR3fy4arWNA1KoS8kVw33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQs\n' +
  'HUfQrSDv+MuSUMAe8jzKE4qW+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1/xAK5D\n' +
  'o2kQ+X5xK9cipRgEKwIDAQAB\n' +
  '-----END PUBLIC KEY-----'

const pubKeys = {
    'test@test.com': {
      '1@RS256': publicKey,
      'default@RS256': publicKey
    }
  }

  const defaultOptions = {
    expiresSkew: 0,
    expiresMax: 0,
    nbfIatSkew: 300,
    fixup: null,
    validators: {
      'aud': () => {
        return true
      },
      'exp': () => {
        return true
      }
    }
  }

const testJwt =
  'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ.eyJhdWQiOiJodHRwczovL2hvc3Qvb2F1dGgvdG9rZW4iLCJpc3MiOiJ0ZXN0QHRlc3QuY29tIiwiaWF0IjoxNTAzMzM1MTY5LCJleHAiOjE1MDMzMzU3NjksInNjb3BlIjpbImh0dHA6Ly9zdHVmZiIsImh0dHA6Ly9zdHVmZjIiXX0.zO278VV6NzwsvBrAIc15mOfwza-FkmLCV28NRXnrI550xw1S1145cS1UsZP5zXxcrk5f4oEgB91Jt6ble76yK5nU68fALUXtfe7xPUkhcOUIw92q_x_Iaaw4z6a71NtyishCfJlbmwkXXEq5YCVAvX3KNDtyPf_fQrAqjzsbgQc'

const testJwtWrongAlg =
  'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzEyOCJ9.eyJhdWQiOiJodHRwczovL2hvc3Qvb2F1dGgvdG9rZW4iLCJpc3MiOiJ0ZXN0QHRlc3QuY29tIiwiaWF0IjoxNTAzMzM2NzU5LCJleHAiOjE1MDMzMzczNTksInNjb3BlIjpbImh0dHA6Ly9zdHVmZiIsImh0dHA6Ly9zdHVmZjIiXX0.12co2gXwBxmZ2uLJecd26bfteCLBx7jgu_9rp2hhKAHWA4qFKm1HcQOZXqDvHkjflQDtNAQ1ZUUf3U8kntUUAmMOjhHx0BspC-xuaTFylZWqj--A2_w9e7JSk46TF_x3e_hZLB3rtyuSEAPMh_nOCsmM-4A2fnQx0Y5p-Bwbt0I'

describe('jwtUtils', () => {
  beforeEach(async () => {

  })
  describe('jwtDecode', () => {  
    it('decodes', () => {
      expect(JwtUtils.jwtDecode(testJwt, pubKeys, audiences, defaultOptions)).toEqual({ "aud": "https://host/oauth/token",
         exp: 1503335769,
         iat: 1503335169,
         iss: "test@test.com",
         scope: [
           "http://stuff",
           "http://stuff2",
         ]
    })
    })  
    it('too few spaces', () => {
      expect(() => JwtUtils.jwtDecode('hello.test', pubKeys, audiences)).toThrow(new JwtVerifyError('JWT does not contain 3 dots'))
    })
    it('invalid json', () => {
      expect(() => JwtUtils.jwtDecode(testJwt.substr(10), pubKeys, audiences)).toThrow(new JwtVerifyError('Unexpected token $ in JSON at position 0'))
    })
    it('wrong alg', () => {
      expect(() => JwtUtils.jwtDecode(testJwtWrongAlg, pubKeys, audiences)).toThrow(new JwtVerifyError('Only alg RS256, RS384, RS512, ES256, ES384, ES512, HS256, HS384 and HS512 are supported'))
    })
  })
})
