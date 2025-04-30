import { JwtServiceAuthError } from './index'

describe('JwtServiceAuthError', () => {
  it('innerError should be null', () => {
    const error = new JwtServiceAuthError('')
    expect(error.context).toEqual({})
  })
})
