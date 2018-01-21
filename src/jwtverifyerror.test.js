// @ts-check
'use strict'

const expect = require('unexpected')

const { JwtServiceAuthError } = require('./index')

describe('JwtServiceAuthError', () => {
  it('innerError should be null', () => {
    let error = new JwtServiceAuthError('')
    expect(error.innerError, 'to be null')
  })
})
