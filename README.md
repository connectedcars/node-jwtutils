# node-jwtutils

[![Build Status](https://travis-ci.org/connectedcars/node-jwtutils.svg?branch=master)](https://travis-ci.org/connectedcars/node-jwtutils)
[![Coverage Status](https://coveralls.io/repos/github/connectedcars/node-jwtutils/badge.svg?branch=master)](https://coveralls.io/github/connectedcars/node-jwtutils?branch=master)

Zero dependency JWT encoding and decoding for Node 6.x and 8.x

Features:

* Encode and decode any RS256, RS384, RS512, ES256, ES384 and ES512 signed tokens
* Support for multiple issuers and keys per issuer.
* Express middleware to validate JWT's

## Background

Most other JWT implementations tend be complex and have a large array of
dependencies because they implement the seldom used JOSE standard.
This often makes the whole JWT encoding/decoding complicated and hard to
understand, something it really should not be.

So the focus of this module has been to make a simple, secure, fast and
flexible set of utility methods to work with JWT's. The code itself is also
easy to understand and less than 200 lines of code, making it much easier to
security audit the code.

Also note doing your own crypto is a bad idea so this module only deals with
the encoding/decoding of the JWT, the underlaying crypto operations are done
by Node's build-in crypto api that uses openssl.

Currently only asymmetric encryption algorithms are supported as this would
also be the only recommend option for production use.

## Samples

* [Integrate with Google Identity Platform](sample/googleoauth2v2/README.md)

## Basic usage

``` javascript
const { JwtUtils, JwtVerifyError } = require('@connectedcars/jwtutils')

const unixNow = Math.floor(Date.now() / 1000)

let jwtHeader = {
  typ: 'JWT',
  alg: 'RS256',
  kid: '1'
}

let jwtBody = {
  aud: 'https://api.domain.tld',
  iss: 'https://jwt.io/',
  sub: 'subject@domain.tld',
  iat: unixNow,
  exp: unixNow + 600,
  scope: ['http://stuff', 'http://stuff2']
}

// Don't use this key for anything but testing as this is the key from jwt.io
const pemEncodedPrivateKey =
  '-----BEGIN RSA PRIVATE KEY-----\n' +
  'MIICWwIBAAKBgQDdlatRjRjogo3WojgGHFHYLugdUWAY9iR3fy4arWNA1KoS8kVw\n' +
  '33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQsHUfQrSDv+MuSUMAe8jzKE4qW\n' +
  '+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1/xAK5Do2kQ+X5xK9cipRgEKwIDAQAB\n' +
  'AoGAD+onAtVye4ic7VR7V50DF9bOnwRwNXrARcDhq9LWNRrRGElESYYTQ6EbatXS\n' +
  '3MCyjjX2eMhu/aF5YhXBwkppwxg+EOmXeh+MzL7Zh284OuPbkglAaGhV9bb6/5Cp\n' +
  'uGb1esyPbYW+Ty2PC0GSZfIXkXs76jXAu9TOBvD0ybc2YlkCQQDywg2R/7t3Q2OE\n' +
  '2+yo382CLJdrlSLVROWKwb4tb2PjhY4XAwV8d1vy0RenxTB+K5Mu57uVSTHtrMK0\n' +
  'GAtFr833AkEA6avx20OHo61Yela/4k5kQDtjEf1N0LfI+BcWZtxsS3jDM3i1Hp0K\n' +
  'Su5rsCPb8acJo5RO26gGVrfAsDcIXKC+bQJAZZ2XIpsitLyPpuiMOvBbzPavd4gY\n' +
  '6Z8KWrfYzJoI/Q9FuBo6rKwl4BFoToD7WIUS+hpkagwWiz+6zLoX1dbOZwJACmH5\n' +
  'fSSjAkLRi54PKJ8TFUeOP15h9sQzydI8zJU+upvDEKZsZc/UhT/SySDOxQ4G/523\n' +
  'Y0sz/OZtSWcol/UMgQJALesy++GdvoIDLfJX5GBQpuFgFenRiRDabxrE9MNUZ2aP\n' +
  'FaFp+DyAe+b4nDwuJaW2LURbr8AEZga7oQj0uYxcYw==\n' +
  '-----END RSA PRIVATE KEY-----'

// let jwt = JwtUtils.encode(pemEncodedPrivateKey, jwtHeader, jwtBody, privateKeyPassword)
let jwt = JwtUtils.encode(pemEncodedPrivateKey, jwtHeader, jwtBody)

// Don't use this key for anything but testing as this is the key from jwt.io
const publicKey =
  '-----BEGIN PUBLIC KEY-----\n' +
  'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDdlatRjRjogo3WojgGHFHYLugd\n' +
  'UWAY9iR3fy4arWNA1KoS8kVw33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQs\n' +
  'HUfQrSDv+MuSUMAe8jzKE4qW+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1/xAK5D\n' +
  'o2kQ+X5xK9cipRgEKwIDAQAB\n' +
  '-----END PUBLIC KEY-----'

const allowedAudinces = ['https://api.domain.tld']

const pubKeys = {
  'https://jwt.io/': {
    '1@RS256': publicKey,
    'default@RS256': publicKey // Will default to this key if the header does not have a kid
  }
}

try {
  let decodedJwtBody = JwtUtils.decode(jwt, pubKeys, allowedAudinces)
} catch (e) {
  if (e instanceof JwtVerifyError) {
    // Can be returned to user
  } else {
    // Should not be returned to user
    console.error(e)
  }
}
```

## Usage of express middleware

``` javascript
const express = require('express')
const { JwtAuthMiddleware, JwtVerifyError } = require('@connectedcars/jwtutils')

// Configuration
const audiences = ['https://api.domain.tld']
const pubKeys = {
  'https://jwt.io/': {
    '1@RS256': publicKey // Fx. use key from before
  },
  'https://jwt.io/custom': { // Overwrite default validation for this issuer
    '1@RS256': { // Same options can also be used directly with decode
      publicKey: publicKey,
      expiresMax: 3600, // Don't allow token that has a lifetime over 1 hour
      expiresSkew: 600, // Allow tokens that expired up to 10 minutes ago
      nbfIatSkew: 300, // Allow tokens that has nbf or iat in the future by up to 5 minutes
    }
  }
}

const app = express()

// Register the middleware
app.use(JwtAuthMiddleware(pubKeys, audiences, user => { // Also supports Promises and async
  if (user.issuer === 'https://jwt.io/') {
    if (!user.subject.match(/^[^@]+@domain\.tld$/)) {
      throw new JwtVerifyError('Issuer https://jwt.io/ only allowed to have subject ending in @domain.tld')
    }
  }
}))

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

app.get('/', (req, res) => {
  res.send(`Hello ${req.user.subject}`)
})
app.listen(3000, () => {
  console.log('Example app listening on port 3000!')
})
```

### Integration with 3rd parties

Google Identity platform:

``` javascript
const { PubkeysHelper } = require('@connectedcars/jwtutils')

// Fetch with Google's public keys every hour
setInterval(() => {
  PubkeysHelper.fetchJwkKeys('https://www.googleapis.com/oauth2/v3/certs')
    .then(keys => {
      pubKeys['https://accounts.google.com'] = keys
    })
    .catch(e => {
      console.log(e)
    })
}, 60 * 60 * 1000)
```

## Usage of service authentication (Google and Github)

``` javascript
const { JwtServiceAuth } = require('./index')
const fs = require('fs')
const r2 = require('r2')

// Wrap your favorite http library
let httpRequestHandler = async (method, url, headers, body) => { // Fx. POST, http://domain.tld, {}, "..."
  // Do http request
  let httpRespone = await r2[method.toLowerCase()](url, { headers, body }).response
  let data = await httpResponse.arrayBuffer()
  return {
    statusCode: httpResponse.status,
    data: data,
    headers: httpResponse.headers
  }
})

let jwtServiceAuth = new JwtServiceAuth(httpRequestHandler)

let gitHubAppPrivateKey = fs.readFileSync("user-appname.2017-01-01.private-key.pem", 'utf8')
let googleServiceAccountKeyfile = fs.readFileSync("user-serviceaccount-12345678.json", 'utf8')

async function getAccessTokens() {
  let githubAppToken = await = jwtServiceAuth.getGithubAccessToken(gitHubAppPrivateKey, 1, 1)
  let googleToken = await jwtServiceAuth.getGoogleAccessToken(googleServiceAccountKeyfile)
}
```

### Documentation

* Github App: https://developer.github.com/apps/building-github-apps/authentication-options-for-github-apps/
* Google Service Account: https://developers.google.com/identity/protocols/OAuth2ServiceAccount

## Generate own keypair

Generate private RSA key:

``` bash
# Here the key is encrypted with aes256
openssl genrsa -aes256 -out private.pem 2048
```

Generate public key from private key:

``` bash
openssl rsa -in private.pem -outform PEM -pubout -out public.pem
```

## Command line helper utils

*NOTE: Does not support nested JSON*

Load private key:

``` bash
jwtencode private.pem
```

Copy/paste to stdin (Ctrl-D to end), the password line is only needed if the private key is encrypted:

``` text
password password-for-private-key
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "1"
}
{
  "iss": "jwt.io",
  "aud": "https://api.domain.tld",
  "sub": "subject@domain.tld",
  "iat": 1504292127,
  "nbf": 1504292127,
  "exp": 1598986470
}
````

``` bash
jwtdecode public.pem 1 RS256 https://jwt.io localhost
```

Copy/paste to stdin (Ctrl-D to end):

``` text
eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IjEifQ.eyJpc3MiOiJodHRwczovL2p3dC5pbyIsImF1ZCI6ImxvY2FsaG9zdCIsInN1YiI6InN1YmplY3RAZG9tYWluLnRsZCIsImlhdCI6MTUwNDI5MjEyNywibmJmIjoxNTA0MjkyMTI3LCJleHAiOjE1OTg5ODY0NzB9.0L5AWwUF3EleBqnQ6V0Lqa36jCccP4A7cAFHHIY1b-oE7pxCoFr8gnAOrlc16N0WUPI6O17JT79kQIPR-LjFm-BgBycBw4eEFYb8z7iXA-zqgQz4ajZXlIljJtJUBbTupbnzEiBKjEFnTxYqb-vUm-TDwTMPaYzBxqqfOrrvKlw
````
