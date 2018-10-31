'use strict'

const path = require('path')
const express = require('express')
const axios = require('axios')

const {
  JwtAuthMiddleware,
  JwtVerifyError,
  PubkeysHelper
} = require('../../src/.')

let pubkeysHelper = new PubkeysHelper()
const pubKeys = {}

const applicationId = process.argv[2]
const tenant = process.argv[3]
const redirectUri = 'http://localhost:3000/'

const issuer = `https://login.microsoftonline.com/${tenant}/v2.0`
const openidConfigEndpoint = `https://login.microsoftonline.com/${tenant}/v2.0/.well-known/openid-configuration`
const audiences = [applicationId]

class OpenIdConnectHelper {
  /**
   *
   * @param {Object} publicKeys
   * @param {string} url
   * @param {string} issuer
   * @param {Object} [options]
   */
  constructor(publicKeys, url, issuer, options = {}) {
    this.config = null
    this.url = url
    this.issuer = issuer
    this.publicKeys = publicKeys
    axios
      .get(url)
      .then(res => {
        if (res.status === 200 && res.data) {
          this.config = res.data
          if (!this.config.jwks_uri) {
            throw new Error('JWK uri not set')
          }
          return this.updatePubkeys()
        } else {
          throw Error('Some error')
        }
      })
      .catch(e => {
        console.error(e)
      })

    setInterval(() => {
      this.updatePubkeys().catch(e => {
        console.error(`Failed to fetch pubkeys: ${e}`)
      })
    }, 60 * 60 * 1000) // TODO: Make it optional
  }

  updatePubkeys() {
    // TODO: Add filtering on issue for keys
    return pubkeysHelper
      .fetchJwkKeys(this.config.jwks_uri, {
        algorithms: this.config.id_token_signing_alg_values_supported || []
      })
      .then(keys => {
        // TODO Validate keys
        this.publicKeys[this.issuer] = keys
      })
  }
}

if (process.argv.length <= 2) {
  console.error('node index.js "application id" "tenant"')
  process.exit(255)
}

let openIdConnectHelper = new OpenIdConnectHelper(
  pubKeys,
  openidConfigEndpoint,
  issuer
)

const app = express()
app.use('/', express.static(path.join(__dirname, 'public')))

app.get('/config', (req, res) => {
  let loginUrl =
    `${openIdConnectHelper.config.authorization_endpoint}?` +
    `client_id=${applicationId}` +
    `&redirect_uri=${encodeURI(redirectUri)}` +
    '&response_type=id_token' +
    '&scope=openid email profile' +
    '&response_mode=fragment' +
    '&state=12345' +
    '&nonce=678910'
  res.json({
    loginUrl: loginUrl
  })
})

app.use(
  '/api',
  JwtAuthMiddleware(pubKeys, audiences, user => {
    // Use e-mail as subject for google tokens
    if (user.issuer === issuer) {
      user.subject = user.body.email
    }
  })
)

// Register an error handler to return 401 errors
app.use((err, req, res, next) => {
  let test = pubKeys
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
