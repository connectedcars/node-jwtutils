/* eslint-disable no-console */
import axios from 'axios'
import express, { Request, Response } from 'express'
import path from 'path'

import { JwtAuthMiddleware, JwtVerifyError, PublicKey } from '../../src/.'
import { jwkToPem } from '../../src/jwkutils'

if (process.argv.length <= 2) {
  console.error('node index.js "google-oauth-cclientid"')
  process.exit(255)
}

const audiences = [process.argv[2]]
const pubKeys: Record<string, Record<string, PublicKey>> = {}
const revokedTokens = {}

const app = express()
app.use('/', express.static(path.join(__dirname, 'public')))

app.use(
  '/api',
  JwtAuthMiddleware(
    pubKeys,
    revokedTokens,
    audiences,
    (user: Record<string, string> & { body: Record<string, string> }) => {
      // Use e-mail as subject for google tokens
      if (user.issuer === 'https://accounts.google.com') {
        user.subject = user.body.email
      }
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

// Fetch googles public keys every hour
await fetchGoogleJWK()
setInterval(async () => {
  await fetchGoogleJWK()
}, 60 * 60 * 1000)

async function fetchGoogleJWK(): Promise<void> {
  return await fetchJWK('https://www.googleapis.com/oauth2/v3/certs')
    .then(keys => {
      pubKeys['https://accounts.google.com'] = keys
    })
    .catch(e => {
      console.log(e)
    })
}

async function fetchJWK(url: string): Promise<Record<string, PublicKey>> {
  try {
    const res = await axios.get(url)
    const data = JSON.parse(res.data)
    if (!data.keys) {
      throw new Error(`Unexpected data structure:\n${res.data}`)
    }
    const pubKeys: Record<string, PublicKey> = {}
    for (const key of data.keys) {
      const rsaPublicKeyPem = jwkToPem(key)
      pubKeys[`${key.kid}@${key.alg}`] = { publicKey: rsaPublicKeyPem }
    }
    return pubKeys
  } catch (e) {
    throw new Error(e)
  }
}
