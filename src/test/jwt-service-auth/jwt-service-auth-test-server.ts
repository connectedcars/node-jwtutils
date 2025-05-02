import { HttpServer } from '@connectedcars/test'
import querystring from 'querystring'

import { jwtUtils, type PublicKeys } from '../../index'
import { rsaPublicKey } from '../test-resources'

const pubKeys: PublicKeys = {
  'buildstatus@nversion-168820.iam.gserviceaccount.com': {
    '76d81ae69ce620a517b140fc73dbae61e88b34bc@RS256': rsaPublicKey
  },
  '1': {
    'default@RS256': {
      publicKey: rsaPublicKey,
      validators: {
        aud: () => {
          return true
        }
      }
    }
  }
}

export class JwtServiceAuthTestServer extends HttpServer {
  public constructor() {
    super({}, async (req, res) => {
      switch (req.url) {
        case '/oauth2/v4/token': {
          const body = this.getLastTextRequest()?.body

          if (!body) {
            res.statusCode = 400
            res.end(JSON.stringify('Expected valid string body'))

            return
          }

          if (body) {
            const token = querystring.unescape(body.replace(/^.+assertion=([^&]+).*?$/, '$1'))
            const decodedBody = jwtUtils.decode(token, pubKeys, ['https://www.googleapis.com/oauth2/v4/token'])
            if (decodedBody.scope !== '') {
              res.statusCode = 200
              res.end(JSON.stringify({ access_token: 'ok', expires_in: 3600 }))
            } else {
              res.statusCode = 400
              res.end(JSON.stringify({ error: 'scopes not set' }))
            }
          } else {
            res.statusCode = 400
            res.end(JSON.stringify({ error: 'not valid' }))
          }

          return res
        }

        case '/app/installations/1/access_tokens': {
          if (!req.headers['authorization']) {
            res.statusCode = 400
            return res.end(JSON.stringify('Auth error'))
          }

          const token = req.headers['authorization'].replace(/^Bearer (.+)$/, '$1')
          const decodedBody = jwtUtils.decode(token, pubKeys, [])

          if (!decodedBody) {
            res.statusCode = 400
            return res.end(JSON.stringify('Decoding failure'))
          }

          res.statusCode = 201
          res.end(
            JSON.stringify({
              token: 'v1.1f699f1069f60xxx',
              expires_at: new Date(new Date().getTime() + 3600 * 1000).toISOString()
            })
          )

          return res
        }

        default: {
          res.statusCode = 400
          return res.end(JSON.stringify({ description: 'response.statusCode not 200' }))
        }
      }
    })
  }
}
