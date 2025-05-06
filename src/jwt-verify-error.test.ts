import { JwtVerifyError } from '.'

describe('JwtVerifyError', () => {
  it('constructs a JwtVerifyError', () => {
    const error1 = new JwtVerifyError('')
    expect(error1.name).toBe('JwtVerifyError')
    expect(error1.message).toBe('')
    expect(error1.innerError).toBeNull()

    const error2 = new JwtVerifyError('message', new Error('Oh noes'))
    expect(error2.name).toBe('JwtVerifyError')
    expect(error2.message).toBe('message')
    expect(error2.innerError).toEqual(new Error('Oh noes'))
  })
})
