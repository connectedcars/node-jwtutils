'use strict'

const expect = require('unexpected')
const jwtUtils = require('./index')

describe('jwtUtils', () => {
  describe('decode', () => {
    it('invalid header and body', () => {
      expect(
        () => {
          jwtUtils.encode('', '', '')
        },
        'to throw',
        'both header and body should be of type object'
      )
    })
    it('empty header and body', () => {
      expect(
        () => {
          jwtUtils.encode('', {}, {})
        },
        'to throw',
        'Only alg RS256, RS384, RS512, ES256, ES384 and ES512 are supported'
      )
    })
  })
})
