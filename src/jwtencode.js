// @ts-check
'use strict'

const crypto = require('crypto')

const base64UrlSafe = require('./base64urlsafe')

function jwtEncode(privateKey, header, body, privateKeyPassword = null) {
  if (
    typeof header !== 'object' ||
    Array.isArray(header) ||
    typeof body !== 'object' ||
    Array.isArray(body)
  ) {
    throw new Error('both header and body should be of type object')
  }

  // ES256
  let algo = null
  switch (header.alg) {
    case 'RS256':
      algo = 'RSA-SHA256'
      break
    case 'RS384':
      algo = 'RSA-SHA384'
      break
    case 'RS512':
      algo = 'RSA-SHA512'
      break
    case 'ES256':
      algo = 'sha256'
      break
    case 'ES384':
      algo = 'sha256'
      break
    case 'ES512':
      algo = 'sha512'
      break
    default:
      throw new Error(
        'Only alg RS256, RS384, RS512, ES256, ES384 and ES512 are supported'
      )
  }

  const sign = crypto.createSign(algo)

  // Base64 encode header and body
  let headerBase64 = base64UrlSafe.encode(Buffer.from(JSON.stringify(header)))
  let bodyBase64 = base64UrlSafe.encode(Buffer.from(JSON.stringify(body)))
  let headerBodyBase64 = headerBase64 + '.' + bodyBase64

  // Add header and body of JWT to sign
  sign.update(headerBodyBase64, 'utf8')
  sign.end()

  // Sign with privatekey
  let signatureBuffer
  if (privateKeyPassword !== null) {
    signatureBuffer = sign.sign({
      key: privateKey,
      passphrase: privateKeyPassword
    })
  } else {
    signatureBuffer = sign.sign(privateKey)
  }

  // Construct final JWT
  let signatureBase64 = base64UrlSafe.encode(signatureBuffer)
  return headerBodyBase64 + '.' + signatureBase64
}

module.exports = jwtEncode
