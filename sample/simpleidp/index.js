'use strict'

const path = require('path')
const express = require('express')
const bodyParser = require('body-parser')
const { JwtUtils } = require('../../src/.')
const crypto = require('crypto')

// Don't use this key, generate your own and load it from a safe place
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

const users = {
  admin: {
    hash: '377feab95ad6e891272d45ad717723d75acf2efd92cbf931d72d1052636635c831d8693c64c42790e877d0a7e3a83b452c960145175025fc853bec2145984885',
    salt: 'd75acf2efd9'
  }
}

const app = express()
app.use('/', express.static(path.join(__dirname, 'public')))

app.use(bodyParser.json())
app.use('/api/login', (req, res) => {
  // Do your authentication login here, you could user modules like passport to do it for you also
  let password = req.body.password
  let username = req.body.username

  let user = users[username]
  if (!user) {
    return res.sendStatus(403)
  }
  
  // Here we do a simple hashed password check  
  crypto.pbkdf2(password, user.salt, 100000, 64, 'sha512', (err, derivedKey) => {
    if (err) {
      return res.sendStatus(403)
    }

    let hashedPasswordBytes = Buffer.from(user.hash, 'hex')
    if (!crypto.timingSafeEqual(hashedPasswordBytes, derivedKey)) {
      return res.sendStatus(403)
    }

    // Generate token
    const unixNow = Math.floor(Date.now() / 1000)
    let jwtHeader = {
      typ: 'JWT',
      alg: 'RS256',
      kid: '1'
    }
    let jwtBody = {
      iss: 'simpleidp',
      sub: req.body.user,
      aud: 'simpleservice',
      exp: unixNow + 3600, // One hour expiry
      iat: unixNow,
      nbf: unixNow - 300, // Allow consumers a 5 mins backwards timeskew
      clt: 0
    }

    let signedJwt = JwtUtils.encode(pemEncodedPrivateKey, jwtHeader, jwtBody)
    res.json({
      token: signedJwt,
      expires: 3600
    })
  })
})

app.listen(3000, () => {
  console.log('Example app listening on port 3000!')
})
