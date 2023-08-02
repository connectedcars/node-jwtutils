/* eslint-disable no-console */
import axios from 'axios'
import express, { Request, Response } from 'express'
import path from 'path'

import { JwtAuthMiddleware, JwtVerifyError, PubkeysHelper, PublicKey } from '../../src/.'

if (process.argv.length < 4) {
  console.error('node index.js "application id" "tenant"')
  process.exit(255)
}

const pubkeysHelper = new PubkeysHelper()
const pubKeys: Record<string, Record<string, string | PublicKey>> = {}
const revokedTokens = {}

const applicationId = process.argv[2]
const tenants = process.argv[3].split(',')
const redirectUri = 'http://localhost:3000/'

const audiences = [applicationId]

const openIdConnectConfigCache: Record<string, OpenIdConnectConfig> = {}

// Fetch all OpenIdConnect configs
for (const tenant of tenants) {
  const issuer = `https://login.microsoftonline.com/${tenant}/v2.0`
  const openidConfigEndpoint = `https://login.microsoftonline.com/${tenant}/v2.0/.well-known/openid-configuration`

  fetchOpenIdConnectConfig(openidConfigEndpoint)
    .then(async config => {
      const updatePubkeys = (jwksUri: string, defaultAlgorithms: string[]): Promise<void> => {
        return pubkeysHelper
          .fetchJwkKeys(jwksUri, {
            defaultAlgorithms: defaultAlgorithms || []
          })
          .then(keys => {
            if (keys) {
              pubKeys[issuer] = keys
            }
          })
      }
      // Do initial fetch of pubkeys
      await updatePubkeys(config.jwksUri, config.idTokenSigningAlgValuesSupported)

      // Schedule pubkey update
      setInterval(() => {
        updatePubkeys(config.jwksUri, config.idTokenSigningAlgValuesSupported).catch(e => {
          console.error(`Failed to fetch pubkeys: ${e}`)
        })
      }, 3600 * 1000)
    })
    .catch(e => {
      console.error(`Failed to fetch open id connect config: ${e}`)
    })
}

interface OpenIdConnectConfig {
  authorizationEndpoint: string
  jwksUri: string
  issuer: string
  idTokenSigningAlgValuesSupported: string[]
}

// TODO: Do cache timeout/invalidation
async function fetchOpenIdConnectConfig(openidConfigEndpoint: string): Promise<OpenIdConnectConfig> {
  // Use cached version of config if we have it
  const config = openIdConnectConfigCache[openidConfigEndpoint]
  if (config) {
    return Promise.resolve(config)
  }
  // Fetch config
  return axios.get(openidConfigEndpoint).then(res => {
    if (res.status === 200 && res.data) {
      if (!res.data.jwksUri) {
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
  const username = req.query['username']
  if (username && typeof username === 'string') {
    const match = username.match(/^[^@]+@(.+)$/)
    if (match) {
      const domain = match[1]
      fetchOpenIdConnectConfig(`https://login.microsoftonline.com/${domain}/v2.0/.well-known/openid-configuration`)
        .then(config => {
          if (!pubKeys[config.issuer]) {
            return res.status(401).send({ error: 'No config for your' })
          }
          return res.json({
            loginUrl:
              `${config.authorizationEndpoint}?` +
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
  JwtAuthMiddleware(
    pubKeys,
    revokedTokens,
    audiences,
    (user: Record<string, string> & { body: Record<string, string> }) => {
      // Use e-mail as subject from the token
      // TODO: Validate that the issues has a email in the token
      user.subject = user.body.preferred_username
    }
  )
)

// Register an error handler to return 401 errors
// eslint-disable-next-line @typescript-eslint/no-unused-vars
app.use((err: Error, req: Request, res: Response, _next: (err?: Error | null) => void) => {
  if (err instanceof JwtVerifyError) {
    if (err.context) {
      console.error(`Failed with: ${err.context.message}`)
    }
    res.status(401).send(err.message)
  } else {
    res.status(500).send('Unknown error')
  }
})

app.use('/api/hello', (req: Request & { user?: Record<string, unknown> }, res: Response) => {
  if (req.user) {
    res.json({ message: `Hello World: ${req.user.subject}` })
  }
})

app.listen(3000, () => {
  console.log('Example app listening on port 3000!')
})
