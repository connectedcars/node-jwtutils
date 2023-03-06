'use strict'

const path = require('path')
const express = require('express')
const { default: axios } = require('axios')

const {
  JwtAuthMiddleware,
  JwtVerifyError,
  PubkeysHelper
} = require('../../src/.')

if (process.argv.length < 4) {
  console.error('node index.js "application id" "tenant"')
  process.exit(255)
}

let pubkeysHelper = new PubkeysHelper()
const pubKeys = {}
const revokedTokens = {}

const applicationId = process.argv[2]
const tenants = process.argv[3].split(',')
const redirectUri = 'http://localhost:3000/'

const audiences = [applicationId]

let openIdConnectConfigCache = {}

// Fetch all OpenIdConnect configs
for (let tenant of tenants) {
  const issuer = `https://login.microsoftonline.com/${tenant}/v2.0`
  const openidConfigEndpoint = `https://login.microsoftonline.com/${tenant}/v2.0/.well-known/openid-configuration`

  fetchOpenIdConnectConfig(openidConfigEndpoint)
    .then(config => {
      let updatePubkeys = (jwksUri, defaultAlgorithms) => {
        return pubkeysHelper
          .fetchJwkKeys(jwksUri, {
            defaultAlgorithms: defaultAlgorithms || []
          })
          .then(keys => {
            pubKeys[issuer] = keys
          })
      }
      // Do initial fetch of pubkeys
      updatePubkeys(
        config.jwks_uri,
        config.id_token_signing_alg_values_supported
      )

      // Schedule pubkey update
      setInterval(() => {
        updatePubkeys(
          config.jwks_uri,
          config.id_token_signing_alg_values_supported
        ).catch(e => {
          console.error(`Failed to fetch pubkeys: ${e}`)
        })
      }, 3600 * 1000)
    })
    .catch(e => {
      console.error(`Failed to fetch open id connect config: ${e}`)
    })
}

/**
 * @typedef OpenIdConnectConfig
 * @property {string} authorization_endpoint
 * @property {string} jwks_uri
 * @property {string} issuer
 * @property {Array<string>} id_token_signing_alg_values_supported
 */

/**
 * Fetch Open ID Connect configuration
 * @param {string} openidConfigEndpoint
 * @returns {Promise<OpenIdConnectConfig>}
 */
// TODO: Do cache timeout/invalidation
function fetchOpenIdConnectConfig(openidConfigEndpoint) {
  // Use cached version of config if we have it
  let config = openIdConnectConfigCache[openidConfigEndpoint]
  if (config) {
    return Promise.resolve(config)
  }
  // Fetch config
  return axios.get(openidConfigEndpoint).then(res => {
    if (res.status === 200 && res.data) {
      if (!res.data.jwks_uri) {
        throw new Error('JWK uri not set')
      }
      openIdConnectConfigCache[openidConfigEndpoint] = res.data
      return res.data
    } else {
      throw Error('Some error')
    }
  })
}

const app = express()
app.use('/', express.static(path.join(__dirname, 'public')))

app.get('/config', (req, res) => {
  let username = req.query['username']
  if (username) {
    let match = username.match(/^[^@]+@(.+)$/)
    if (match) {
      let domain = match[1]
      fetchOpenIdConnectConfig(
        `https://login.microsoftonline.com/${domain}/v2.0/.well-known/openid-configuration`
      )
        .then(config => {
          if (!pubKeys[config.issuer]) {
            return res.status(401).send({ error: 'No config for your' })
          }
          res.json({
            loginUrl:
              `${config.authorization_endpoint}?` +
              `client_id=${applicationId}` +
              `&redirect_uri=${encodeURI(redirectUri)}` +
              '&response_type=id_token' +
              '&scope=openid profile email' +
              '&response_mode=fragment' +
              '&state=12345' +
              '&nonce=678910' +
              '&prompt=consent'
          })
        })
        .catch(e => {
          console.error(e)
        })
    }
  }
})

app.use(
  '/api',
  JwtAuthMiddleware(pubKeys, revokedTokens, audiences, user => {
    // Use e-mail as subject from the token
    // TODO: Validate that the issues has a email in the token
    user.subject = user.body.preferred_username
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
