import { PubkeysHelper } from './pubkeys-helper'
import { PubkeysHelperTestServer } from './test/pubkeys-helper/pubkeys-helper-test-server'

const expectedKeysResponse = {
  '26c018b233fe2eef47fedbbdd9398170fc9b29d8@RS256': {
    publicKey:
      '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5miiKafEc9VfN6Io1H6/\nqzPYhHFUhh9/OIA3JQ7hlvv3ydcBFbZwuMJGFWZXTh+C5F/0mDsFo6H524tlGUAe\nagEZV7gnEou1t4jJ78Gdi7qQXcJtOHJRK2gEz/RREICxCil1ybT7pdc/PgrhHr32\nzszA4hyXVL6nts6APfTXK6oSlfvbpU5prGyLOL5KwAp+ALz0lJmoh0oj9g3QgGAZ\nkuoAHj64G49ws1k54748cj9Y+YwcNV00zwvdH/XU0xKOiksC/O/FArKc7bhaiC57\nFkPJ9NFOcZhNZ8PknHXVEENSxT6YFgVTNDDBenZDvAX2DblgZjc6n/GyZZq5AIl3\nuQIDAQAB\n-----END PUBLIC KEY-----'
  },
  'ba4ded7f5a92429f233561a36ff613ed38762c3d@RS256': {
    publicKey:
      '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxy7mPuuYEsn9on4GH7gf\noHDQnCabyGa3RgEhL8P7GejHUZswyaVRUmCcTm47Yf6w3dlCVVaO7UBP3kpjn3qj\nbSzMtKklVvZ51wX7OinMY1TGRKmZAK6S0I5n7WTyaXwT/QDVh1JEsK7Smi7wGfOi\nKlVlOd/DPdPhIgBV7qG55amLyurKf3WI2yEthK/BgLZezbv3hKDdyr56qi27BobL\nf263IRl2BepkVDcMnFWuNH4UVr2AqyoyjXbAmw7iNAz6LN0955r2qacgT+BfRbhN\nw9AkdJ/D1EFKnuwvuVIgZT61Hax2yIznOnnoP1pwZYtVoW2WM9DYIa0St8ZT7SOH\n9QIDAQAB\n-----END PUBLIC KEY-----'
  },
  '9c37bf73343adb93920a7ae80260b0e57684551e@RS256': {
    publicKey:
      '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArZ/JRz8H+Y5tD1bykrqi\ncWgtGmlX/nGFl7NM/xq/P3vJwSYYeOVPXfrugYIbKZETPe3T3eBrXibgGkv4PdGB\n5j3jrEzqENkqZd3xSeTCrfv1SBLptzid7Y4dyeRyJGY0/GfrRb7yCMkeq+87KpwA\n6hww0aAQx5jc9tZBdv9XvS7efWhJtoeBrHhSOUMcaujBZst2V9/owud1i+WfOemS\nKZIXTkobENGLTbTOahZ0YU8jazq1jptWiAsyGlFIwOQR8e6dM38M9AgznGN8vggr\nS/NnW9RudicWQey19uOcUiMRCbEA2d6lfv0YGkQlOaAdQrpyi4fWieT1qR5BvVjH\nfQIDAQAB\n-----END PUBLIC KEY-----'
  }
}

describe('PubkeysHelper', () => {
  const testServer = new PubkeysHelperTestServer()
  let pubkeysHelper: PubkeysHelper
  let baseUrl: string

  beforeAll(async () => {
    await testServer.start()
    pubkeysHelper = new PubkeysHelper()
    baseUrl = `http://localhost:${testServer.listenPort}`
  })

  afterEach(() => {
    testServer.reset()
  })

  afterAll(async () => {
    await testServer.stop()
  })

  it('fetches jwk keys with options', async () => {
    const pubkeys = await pubkeysHelper.fetchJwkKeys(`${baseUrl}/publickeys`, {
      expiresSkew: 25200
    })

    return expect(pubkeys).toEqual({
      '26c018b233fe2eef47fedbbdd9398170fc9b29d8@RS256': {
        ...expectedKeysResponse['26c018b233fe2eef47fedbbdd9398170fc9b29d8@RS256'],
        expiresSkew: 25200
      },
      'ba4ded7f5a92429f233561a36ff613ed38762c3d@RS256': {
        ...expectedKeysResponse['ba4ded7f5a92429f233561a36ff613ed38762c3d@RS256'],
        expiresSkew: 25200
      },
      '9c37bf73343adb93920a7ae80260b0e57684551e@RS256': {
        ...expectedKeysResponse['9c37bf73343adb93920a7ae80260b0e57684551e@RS256'],
        expiresSkew: 25200
      }
    })
  })

  it('fetches jwk keys', async () => {
    const output = await pubkeysHelper.fetchJwkKeys(`${baseUrl}/publickeys`)

    expect(output).toEqual(expectedKeysResponse)
  })

  it('fetches jwk keys with empty keys', async () => {
    await expect(pubkeysHelper.fetchJwkKeys(`${baseUrl}/emptykeys`)).rejects.toThrow(
      new Error(`No keys found in response from ${baseUrl}/emptykeys`)
    )
  })

  it('fetches jwk keys with empty json', async () => {
    await expect(pubkeysHelper.fetchJwkKeys(`${baseUrl}/emptyjson`)).rejects.toThrow(
      new Error(`Response from ${baseUrl}/emptyjson not in expected format: Missing array property keys`)
    )
  })
})
