import { JwtVerifyError } from './index'

describe('JwtVerifyError', () => {
  it('constructs a JwtVerifyError', () => {
    const error = new JwtVerifyError('')

    expect(error.name).toBe('JwtVerifyError')
    expect(error.context).toEqual({})
  })
})
