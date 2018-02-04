const expect = require('unexpected')
const PubkeysHelper = require('./pubkeyshelper')
const { createTestHttpServer } = require('./testutils')

let jwkResponse = {
  keys: [
    {
      kty: 'RSA',
      alg: 'RS256',
      use: 'sig',
      kid: '26c018b233fe2eef47fedbbdd9398170fc9b29d8',
      n:
        '5miiKafEc9VfN6Io1H6_qzPYhHFUhh9_OIA3JQ7hlvv3ydcBFbZwuMJGFWZXTh-C5F_0mDsFo6H524tlGUAeagEZV7gnEou1t4jJ78Gdi7qQXcJtOHJRK2gEz_RREICxCil1ybT7pdc_PgrhHr32zszA4hyXVL6nts6APfTXK6oSlfvbpU5prGyLOL5KwAp-ALz0lJmoh0oj9g3QgGAZkuoAHj64G49ws1k54748cj9Y-YwcNV00zwvdH_XU0xKOiksC_O_FArKc7bhaiC57FkPJ9NFOcZhNZ8PknHXVEENSxT6YFgVTNDDBenZDvAX2DblgZjc6n_GyZZq5AIl3uQ',
      e: 'AQAB'
    },
    {
      kty: 'RSA',
      alg: 'RS256',
      use: 'sig',
      kid: 'ba4ded7f5a92429f233561a36ff613ed38762c3d',
      n:
        'xy7mPuuYEsn9on4GH7gfoHDQnCabyGa3RgEhL8P7GejHUZswyaVRUmCcTm47Yf6w3dlCVVaO7UBP3kpjn3qjbSzMtKklVvZ51wX7OinMY1TGRKmZAK6S0I5n7WTyaXwT_QDVh1JEsK7Smi7wGfOiKlVlOd_DPdPhIgBV7qG55amLyurKf3WI2yEthK_BgLZezbv3hKDdyr56qi27BobLf263IRl2BepkVDcMnFWuNH4UVr2AqyoyjXbAmw7iNAz6LN0955r2qacgT-BfRbhNw9AkdJ_D1EFKnuwvuVIgZT61Hax2yIznOnnoP1pwZYtVoW2WM9DYIa0St8ZT7SOH9Q',
      e: 'AQAB'
    },
    {
      kty: 'RSA',
      alg: 'RS256',
      use: 'sig',
      kid: '9c37bf73343adb93920a7ae80260b0e57684551e',
      n:
        'rZ_JRz8H-Y5tD1bykrqicWgtGmlX_nGFl7NM_xq_P3vJwSYYeOVPXfrugYIbKZETPe3T3eBrXibgGkv4PdGB5j3jrEzqENkqZd3xSeTCrfv1SBLptzid7Y4dyeRyJGY0_GfrRb7yCMkeq-87KpwA6hww0aAQx5jc9tZBdv9XvS7efWhJtoeBrHhSOUMcaujBZst2V9_owud1i-WfOemSKZIXTkobENGLTbTOahZ0YU8jazq1jptWiAsyGlFIwOQR8e6dM38M9AgznGN8vggrS_NnW9RudicWQey19uOcUiMRCbEA2d6lfv0YGkQlOaAdQrpyi4fWieT1qR5BvVjHfQ',
      e: 'AQAB'
    }
  ]
}

let expectedKeysResponse = {
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

let pubkeysHelper = new PubkeysHelper((method, url, headers, body) => {
  if (url === 'http://localhost/pubkeys') {
    return Promise.resolve({
      statusCode: 200,
      statusMessage: 'OK',
      data: Buffer.from(JSON.stringify(jwkResponse, null, 2)),
      headers: {}
    })
  } else if (url === 'http://localhost/emptykeys') {
    return Promise.resolve({
      statusCode: 200,
      statusMessage: 'OK',
      data: Buffer.from(JSON.stringify({ keys: [] }, null, 2)),
      headers: {}
    })
  } else if (url === 'http://localhost/emptyjson') {
    return Promise.resolve({
      statusCode: 200,
      statusMessage: 'OK',
      data: Buffer.from(JSON.stringify({}, null, 2)),
      headers: {}
    })
  } else {
    return Promise.resolve({
      statusCode: 404,
      statusMessage: 'File not found',
      data: Buffer.from(''),
      headers: {}
    })
  }
})

let pubkeysHelperDefault = new PubkeysHelper()

describe('PubkeysHelper', () => {
  let [httpServer, listenPromise] = createTestHttpServer((req, res) => {
    if (req.url === '/pubkeys') {
      res.statusCode = 200
      res.end(JSON.stringify(jwkResponse))
    } else {
      res.statusCode = 404
      res.end()
    }
  })

  let baseUrl = null
  before(done => {
    listenPromise.then(result => {
      baseUrl = `http://localhost:${result.port}`
      console.log(`Listining on ${result.hostname}:${result.port}`)
      done()
    })
  })

  after(() => {
    httpServer.close()
  })

  it('fetchJwkKeys', () => {
    let pubkeys = pubkeysHelper.fetchJwkKeys('http://localhost/pubkeys')
    return expect(pubkeys, 'to be fulfilled with', expectedKeysResponse)
  })
  it('fetchJwkKeys with static method', () => {
    let pubkeys = PubkeysHelper.fetchJwkKeys(`${baseUrl}/pubkeys`)
    return expect(pubkeys, 'to be fulfilled with', expectedKeysResponse)
  })
  it('fetchJwkKeys with default http handler', () => {
    let pubkeys = pubkeysHelperDefault.fetchJwkKeys(`${baseUrl}/pubkeys`)
    return expect(pubkeys, 'to be fulfilled with', expectedKeysResponse)
  })
  it('fetchJwkKeys with options', () => {
    let pubkeys = pubkeysHelper.fetchJwkKeys('http://localhost/pubkeys', {
      expiresSkew: 25200
    })
    return expect(pubkeys, 'to be fulfilled with', {
      '26c018b233fe2eef47fedbbdd9398170fc9b29d8@RS256': {
        publicKey:
          '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA5miiKafEc9VfN6Io1H6/\nqzPYhHFUhh9/OIA3JQ7hlvv3ydcBFbZwuMJGFWZXTh+C5F/0mDsFo6H524tlGUAe\nagEZV7gnEou1t4jJ78Gdi7qQXcJtOHJRK2gEz/RREICxCil1ybT7pdc/PgrhHr32\nzszA4hyXVL6nts6APfTXK6oSlfvbpU5prGyLOL5KwAp+ALz0lJmoh0oj9g3QgGAZ\nkuoAHj64G49ws1k54748cj9Y+YwcNV00zwvdH/XU0xKOiksC/O/FArKc7bhaiC57\nFkPJ9NFOcZhNZ8PknHXVEENSxT6YFgVTNDDBenZDvAX2DblgZjc6n/GyZZq5AIl3\nuQIDAQAB\n-----END PUBLIC KEY-----',
        expiresSkew: 25200
      },
      'ba4ded7f5a92429f233561a36ff613ed38762c3d@RS256': {
        publicKey:
          '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxy7mPuuYEsn9on4GH7gf\noHDQnCabyGa3RgEhL8P7GejHUZswyaVRUmCcTm47Yf6w3dlCVVaO7UBP3kpjn3qj\nbSzMtKklVvZ51wX7OinMY1TGRKmZAK6S0I5n7WTyaXwT/QDVh1JEsK7Smi7wGfOi\nKlVlOd/DPdPhIgBV7qG55amLyurKf3WI2yEthK/BgLZezbv3hKDdyr56qi27BobL\nf263IRl2BepkVDcMnFWuNH4UVr2AqyoyjXbAmw7iNAz6LN0955r2qacgT+BfRbhN\nw9AkdJ/D1EFKnuwvuVIgZT61Hax2yIznOnnoP1pwZYtVoW2WM9DYIa0St8ZT7SOH\n9QIDAQAB\n-----END PUBLIC KEY-----',
        expiresSkew: 25200
      },
      '9c37bf73343adb93920a7ae80260b0e57684551e@RS256': {
        publicKey:
          '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArZ/JRz8H+Y5tD1bykrqi\ncWgtGmlX/nGFl7NM/xq/P3vJwSYYeOVPXfrugYIbKZETPe3T3eBrXibgGkv4PdGB\n5j3jrEzqENkqZd3xSeTCrfv1SBLptzid7Y4dyeRyJGY0/GfrRb7yCMkeq+87KpwA\n6hww0aAQx5jc9tZBdv9XvS7efWhJtoeBrHhSOUMcaujBZst2V9/owud1i+WfOemS\nKZIXTkobENGLTbTOahZ0YU8jazq1jptWiAsyGlFIwOQR8e6dM38M9AgznGN8vggr\nS/NnW9RudicWQey19uOcUiMRCbEA2d6lfv0YGkQlOaAdQrpyi4fWieT1qR5BvVjH\nfQIDAQAB\n-----END PUBLIC KEY-----',
        expiresSkew: 25200
      }
    })
  })
  it('fetchJwkKeys with empty keys', () => {
    let pubkeys = pubkeysHelper.fetchJwkKeys('http://localhost/emptykeys')
    return expect(
      pubkeys,
      'to be rejected with',
      new Error('No keys found in response from http://localhost/emptykeys')
    )
  })
  it('fetchJwkKeys with empty json', () => {
    let pubkeys = pubkeysHelper.fetchJwkKeys('http://localhost/emptyjson')
    return expect(
      pubkeys,
      'to be rejected with',
      new Error(
        'Response from http://localhost/emptyjson not in expected format: Missing array property keys'
      )
    )
  })
})
