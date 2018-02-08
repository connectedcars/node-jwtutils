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

  let signAlgo = null
  let hmacAlgo = null
  switch (header.alg) {
    case 'RS256':
      signAlgo = 'RSA-SHA256'
      break
    case 'RS384':
      signAlgo = 'RSA-SHA384'
      break
    case 'RS512':
      signAlgo = 'RSA-SHA512'
      break
    case 'ES256':
      signAlgo = 'sha256'
      break
    case 'ES384':
      signAlgo = 'sha384'
      break
    case 'ES512':
      signAlgo = 'sha512'
      break
    case 'HS256':
      hmacAlgo = 'sha256'
      break
    case 'HS384':
      hmacAlgo = 'sha384'
      break
    case 'HS512':
      hmacAlgo = 'sha512'
      break
    default:
      throw new Error(
        'Only alg RS256, RS384, RS512, ES256, ES384, ES512, HS256, HS384 and HS512 are supported'
      )
  }

  // Base64 encode header and body
  let headerBase64 = base64UrlSafe.encode(Buffer.from(JSON.stringify(header)))
  let bodyBase64 = base64UrlSafe.encode(Buffer.from(JSON.stringify(body)))
  let headerBodyBase64 = headerBase64 + '.' + bodyBase64

  let signatureBuffer
  if (signAlgo) {
    const sign = crypto.createSign(signAlgo)
    // Add header and body of JWT to sign
    sign.update(headerBodyBase64, 'utf8')
    sign.end()

    // Sign with privatekey
    if (privateKeyPassword !== null) {
      signatureBuffer = sign.sign({
        key: privateKey,
        passphrase: privateKeyPassword
      })
    } else {
      signatureBuffer = sign.sign(privateKey)
    }
  } else if (hmacAlgo) {
    const hmac = crypto.createHmac(hmacAlgo, privateKeyPassword)
    hmac.update(headerBodyBase64)
    signatureBuffer = hmac.digest()
  }

  // Construct final JWT
  let signatureBase64 = base64UrlSafe.encode(signatureBuffer)
  return headerBodyBase64 + '.' + signatureBase64
}

module.exports = jwtEncode
