# node-jwtutils

[![Build Status](https://travis-ci.org/connectedcars/node-jwtutils.svg?branch=master)](https://travis-ci.org/connectedcars/node-jwtutils)
[![Coverage Status](https://coveralls.io/repos/github/connectedcars/node-jwtutils/badge.svg?branch=master)](https://coveralls.io/github/connectedcars/node-jwtutils?branch=master)

Zero dependency JWT encoding and decoding for Node 6.x and 8.x

This module only supports asymmetric encryption algorithms such as RS256,
RS384, RS512, ES256, ES384 and ES512. It currently does not implement symmetric
 encryption as this is a really bad idea for any production use.

## Usage

``` javascript
const jwtUtils = require('jwtutils')

let jwtHeader = {
  typ: 'JWT',
  alg: 'RS256',
  kid: '1'
}

let jwtBody = {
  aud: 'https://api.domain.tld',
  iss: 'https://auth.domain.tld',
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

// let jwt = jwtUtils.encode(pemEncodedPrivateKey, jwtHeader, jwtBody, privateKeyPassword)
let jwt = jwtUtils.encode(pemEncodedPrivateKey, jwtHeader, jwtBody)

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
  'https://auth.domain.tld': {
    '1@RS256': publicKey,
    'default@RS256': publicKey // Will default to this key if the header does not have a kid
  }
}

try {
  let decodedJwtBody = jwtUtils.decode(jwt, pubKeys, allowedAudinces)
} catch (e) {
  if (e instanceof JwtVerifyError) {
    // Can be returned to user
  } else {
    // Should not be returned to user
    console.error(e)
  }
}
```

## Express authentication middleware

``` javascript
const express = require('express')
const jwtAuthMiddleware = require('./jwtauthmiddleware')

// Configuration
const audiences = ['https://api.domain.tld']
const pubKeys = {
  'https://auth.domain.tld': {
    '1@RS256': publicKey // Fx. use key from before
  }
}

const app = express()

// Register the middleware
app.use(jwtAuthMiddleware(pubKeys, audiences))

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
