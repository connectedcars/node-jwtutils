'use strict'

const crypto = require('crypto')

function jwtEncode(privatekey, header, body) {
  if (
    typeof header !== 'object' ||
    Array.isArray(header) ||
    typeof body !== 'object' ||
    Array.isArray(body)
  ) {
    throw new Error('both header and body should be of type object')
  }

  const hashes = crypto.getHashes()

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
  let headerBase64 = base64EncodeUrlSafe(Buffer.from(JSON.stringify(header)))
  let bodyBase64 = base64EncodeUrlSafe(Buffer.from(JSON.stringify(body)))

  // Add to sign object and sign with privatekey
  sign.update(headerBase64 + '.' + bodyBase64, 'utf8')
  let signatureBase64 = base64EncodeUrlSafe(sign.sign(privatekey))

  return headerBase64 + '.' + bodyBase64 + '.' + signatureBase64
}

function base64EncodeUrlSafe(buffer) {
  return buffer
    .toString('base64')
    .replace(/\+/g, '-') // Convert '+' to '-'
    .replace(/\//g, '_') // Convert '/' to '_'
    .replace(/=+$/, '') // Remove ending '='
}

module.exports = jwtEncode
