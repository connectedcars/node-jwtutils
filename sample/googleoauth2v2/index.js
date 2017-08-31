'use strict'

const path = require('path')

const express = require('express')

const jwtAuthMiddleware = require('../../src/jwtauthmiddleware')
const JwtVerifyError = require('../../src/jwtverifyerror')

const request = require('request')
const jwkToPem = require('jwk-to-pem')

const audiences = [
  '807025168921-ti2uj07r2iammimbneq706at7497gtto.apps.googleusercontent.com'
]

const rsaPublicKey =
  '-----BEGIN PUBLIC KEY-----\n' +
  'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDdlatRjRjogo3WojgGHFHYLugd\n' +
  'UWAY9iR3fy4arWNA1KoS8kVw33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQs\n' +
  'HUfQrSDv+MuSUMAe8jzKE4qW+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1/xAK5D\n' +
  'o2kQ+X5xK9cipRgEKwIDAQAB\n' +
  '-----END PUBLIC KEY-----'

const pubKeys = {
  'http://localhost:3000/auth': {
    '1@RS256': rsaPublicKey
  }
}

const app = express()
app.use('/', express.static(path.join(__dirname, 'public')))

app.use(
  '/api',
  jwtAuthMiddleware(pubKeys, audiences, user => {
    // Use e-mail as subject for google tokens
    if (user.issuer === 'https://accounts.google.com') {
      user.subject = user.body.email
    }
  })
)

// Register an error handler to return 401 errors
app.use((err, req, res, next) => {
  if (err instanceof JwtVerifyError) {
    if (err.innerError) {
      console.error(`Failed with: ${err.innerError.message}`)
    }
    res.status(401).send(err.message)
  } else {
    res.status(500).send('Unknown error')
  }
})

app.use('/api/hello', (req, res) => {
  res.json({ message: `Hello World: ${req.user.subject}` })
})

app.listen(3000, () => {
  console.log('Example app listening on port 3000!')
})

// Fetch googles public keys every hour
fetchGoogleJWK()
setInterval(() => {
  fetchGoogleJWK()
}, 60 * 60 * 1000)

function fetchGoogleJWK() {
  return fetchJWK('https://www.googleapis.com/oauth2/v3/certs')
    .then(keys => {
      pubKeys['https://accounts.google.com'] = keys
    })
    .catch(e => {
      console.log(e)
    })
}

function fetchJWK(url) {
  return new Promise((resolve, reject) => {
    request(url, (error, response, body) => {
      if (error) {
        return reject(error)
      }
      try {
        let data = JSON.parse(body)
        if (!data.keys) {
          return reject(new Error(`Unexpected data structure:\n${body}`))
        }
        let pubKeys = {}
        for (let key of data.keys) {
          let rsaPublicKeyPem = jwkToPem(key)
          pubKeys[`${key.kid}@${key.alg}`] = rsaPublicKeyPem
        }
        resolve(pubKeys)
      } catch (e) {
        reject(e)
      }
    })
  })
}
