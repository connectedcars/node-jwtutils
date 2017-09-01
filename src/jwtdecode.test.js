'use strict'

const expect = require('unexpected')
const { JwtUtils } = require('./index')

const pubKeys = {}
const audiences = []

const testJwt =
  'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjEifQ.eyJhdWQiOiJodHRwczovL2hvc3Qvb2F1dGgvdG9rZW4iLCJpc3MiOiJ0ZXN0QHRlc3QuY29tIiwiaWF0IjoxNTAzMzM1MTY5LCJleHAiOjE1MDMzMzU3NjksInNjb3BlIjpbImh0dHA6Ly9zdHVmZiIsImh0dHA6Ly9zdHVmZjIiXX0.zO278VV6NzwsvBrAIc15mOfwza-FkmLCV28NRXnrI550xw1S1145cS1UsZP5zXxcrk5f4oEgB91Jt6ble76yK5nU68fALUXtfe7xPUkhcOUIw92q_x_Iaaw4z6a71NtyishCfJlbmwkXXEq5YCVAvX3KNDtyPf_fQrAqjzsbgQc'

const testJwtWrongAlg =
  'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJodHRwczovL2hvc3Qvb2F1dGgvdG9rZW4iLCJpc3MiOiJ0ZXN0QHRlc3QuY29tIiwiaWF0IjoxNTAzMzM2NzU5LCJleHAiOjE1MDMzMzczNTksInNjb3BlIjpbImh0dHA6Ly9zdHVmZiIsImh0dHA6Ly9zdHVmZjIiXX0.12co2gXwBxmZ2uLJecd26bfteCLBx7jgu_9rp2hhKAHWA4qFKm1HcQOZXqDvHkjflQDtNAQ1ZUUf3U8kntUUAmMOjhHx0BspC-xuaTFylZWqj--A2_w9e7JSk46TF_x3e_hZLB3rtyuSEAPMh_nOCsmM-4A2fnQx0Y5p-Bwbt0I'

describe('jwtUtils', () => {
  describe('decode', () => {
    it('invalid jwt input', () => {
      expect(
        () => {
          JwtUtils.decode({}, pubKeys, audiences)
        },
        'to throw',
        'jwt needs to a string'
      )
    })
    it('invalid pubKeys input', () => {
      expect(
        () => {
          JwtUtils.decode(testJwt, [], audiences)
        },
        'to throw',
        'publicKeys needs to be a map of { issuer: { keyid: "PEM encoded key" }'
      )
    })
    it('too few spaces', () => {
      expect(
        () => {
          JwtUtils.decode('hello.test', pubKeys, audiences)
        },
        'to throw',
        'JWT does not contain 3 dots'
      )
    })
    it('invalid json', () => {
      expect(
        () => {
          JwtUtils.decode(testJwt.substr(10), pubKeys, audiences)
        },
        'to throw',
        'Unexpected token $ in JSON at position 0'
      )
    })
    it('wrong alg', () => {
      expect(
        () => {
          JwtUtils.decode(testJwtWrongAlg, pubKeys, audiences)
        },
        'to throw',
        'Only alg RS256, RS384, RS512, ES256, ES384 and ES512 are supported'
      )
    })
  })
})
