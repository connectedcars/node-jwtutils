import { HttpServer } from '@connectedcars/test'
import querystring from 'querystring'
import { JwtUtils } from './index'

import { rsaPrivateKey, rsaPublicKey } from './testresources'
import { IncomingMessage, ServerResponse } from 'http'


const pubKeys = {
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
                let chunks = []
                req.on('data', chunk => {
                  chunks.push(chunk)
                })
                return req.on('end', () => {
                    let requestData = Buffer.concat(chunks).toString('utf8')
                    if (requestData) {
                      let token = querystring.unescape(
                        requestData.replace(/^.+assertion=([^&]+).*?$/, '$1')
                      )
                      let body = JwtUtils.decode(token, pubKeys, [
                        'https://www.googleapis.com/oauth2/v4/token'
                      ])
                      if (body.scope !== '') {
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
                  })
            }
            case '/app/installations/1/access_tokens': {
              let token = req.headers['authorization'].replace(/^Bearer (.+)$/, '$1')
              let body = JwtUtils.decode(token, pubKeys, [])
              res.statusCode = 201
              return req.on('end', () => {
                res.end(
                  JSON.stringify({
                    token: 'v1.1f699f1069f60xxx',
                    expires_at: new Date(
                      new Date().getTime() + 3600 * 1000
                    ).toISOString()
                  })
                )
              })
              
            }
            default: {
                res.statusCode = 400
                return res.end(JSON.stringify({ description: 'response.statusCode not 200' }))
              }
            
          
            }
       
      })
     
    }
  }

