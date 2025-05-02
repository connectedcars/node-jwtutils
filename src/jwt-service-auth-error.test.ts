import { JwtServiceAuthError } from '.'

describe('JwtServiceAuthError', () => {
  it('constructs a JwtServiceAuthError', () => {
    const error = new JwtServiceAuthError('')

    expect(error.name).toBe('JwtServiceAuthError')
    expect(error.context).toEqual({})
  })
})
