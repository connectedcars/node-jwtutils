import { HttpServer } from '@connectedcars/test'


const jwkResponse = {
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




export class PubkeysHelperTestServer extends HttpServer {
  public constructor() {
    super({}, async (req, res) => {
      switch (req.method) {
        case 'GET': {
          switch (req.url) {
            case '/publickeys': {
              return res.end(JSON.stringify(
                {
                    statusCode: 200,
                    statusMessage: 'OK',
                    data: Buffer.from(JSON.stringify(jwkResponse, null, 2)),
                    headers: {}
                  })
              )
            }
            case '/emptykeys': {
                return res.end(JSON.stringify(
                  {
                      statusCode: 200,
                      statusMessage: 'OK',
                      data: Buffer.from(JSON.stringify({ keys: [] }, null, 2)),
                      headers: {}
                    })
                )
              }
            case '/emptyjson': {
                return res.end(JSON.stringify(
                    {
                        statusCode: 200,
                        statusMessage: 'OK',
                        data: Buffer.from(JSON.stringify({}, null, 2)),
                        headers: {}
                    })
                )
            }
            default: {
                return res.end({
                    statusCode: 404,
                    statusMessage: 'File not found',
                    data: Buffer.from(''),
                    headers: {}
                  })
            }
          }
        }
      }
      res.statusCode = 404
      res.end()
      return
    })
  }
}