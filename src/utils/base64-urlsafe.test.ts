import { decode, encode } from './base64-urlsafe'

describe('base64-urlsafe', () => {
  const base64 = 'PFufJGSnyligIidN1FqoR2K9TEJYHc14IoPyT6m60n56yzZQ3Y6+vnmymEUuY/4NkTA='
  const buffer = Buffer.from(base64, 'base64')

  it('encodes a buffer as url-safe base64', async () => {
    expect(encode(buffer)).toEqual('PFufJGSnyligIidN1FqoR2K9TEJYHc14IoPyT6m60n56yzZQ3Y6-vnmymEUuY_4NkTA')
  })

  it('decodes a url-safe base64 string to a buffer', async () => {
    expect(decode('PFufJGSnyligIidN1FqoR2K9TEJYHc14IoPyT6m60n56yzZQ3Y6-vnmymEUuY_4NkTA')).toEqual(
      Buffer.from(base64, 'base64')
    )
  })
})
