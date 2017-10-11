'use strict'

const crypto = require('crypto')
const JwtVerifyError = require('./jwtverifyerror.js')

const base64UrlSafe = require('./base64urlsafe')

const defaultOptions = { expiresSkew: 0, expiresMax: 0, nbfIatSkew: 300 }
function jwtDecode(jwt, publicKeys, audiences, options = defaultOptions) {
  if (typeof jwt !== 'string') {
    throw new Error('jwt needs to a string')
  }

  if (typeof publicKeys !== 'object' || Array.isArray(publicKeys)) {
    throw new Error(
      'publicKeys needs to be a map of { issuer: { keyid: "PEM encoded key" }'
    )
  }

  if (!Array.isArray(audiences)) {
    throw new Error('audiences needs to be an array of allowed audiences')
  }

  if (typeof options === 'number') {
    // Backwards compatibility with old api
    options = {
      nbfIatSkew: options
    }
  }

  if (typeof options !== 'object' || Array.isArray(publicKeys)) {
    throw new Error('options needs to a map of { nbfIatSkew: 300, ... }')
  }

  let parts = jwt.split(/\./)
  if (parts.length !== 3) {
    throw new JwtVerifyError('JWT does not contain 3 dots')
  }

  let header = JSON.parse(base64UrlSafe.decode(parts[0]).toString('utf8'))

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
      throw new JwtVerifyError(
        'Only alg RS256, RS384, RS512, ES256, ES384 and ES512 are supported'
      )
  }

  let body = JSON.parse(base64UrlSafe.decode(parts[1]).toString('utf8'))

  if (!body.iss) {
    throw new JwtVerifyError('No issuer set')
  }

  let issuer = publicKeys[body.iss]
  if (!issuer) {
    throw new JwtVerifyError(`Unknown issuer '${body.iss}'`)
  }

  // Find public key
  let pubkey =
    typeof header.kid === 'string'
      ? issuer[`${header.kid}@${header.alg}`]
      : issuer[`default@${header.alg}`]

  let issuerOptions = {}
  if (typeof pubkey === 'object' && pubkey !== null && pubkey.publicKey) {
    issuerOptions = pubkey
    pubkey = pubkey.publicKey
  }

  if (!pubkey) {
    throw new JwtVerifyError(
      `Unknown pubkey id '${header.kid}' for this issuer`
    )
  }

  // Validate signature
  let signature = base64UrlSafe.decode(parts[2])
  const verifier = crypto.createVerify(algo)
  verifier.write(`${parts[0]}.${parts[1]}`, 'utf8')
  verifier.end()
  if (!verifier.verify(pubkey, signature)) {
    throw new JwtVerifyError(
      `Signature verification failed with alg '${header.alg}'`
    )
  }

  let unixNow = Math.floor(Date.now() / 1000)
  let validators = {
    aud: validateAudience,
    exp: validateExpires,
    iat: validateIssuedAt,
    nbf: validateNotBefore
  }
  Object.assign(validators, options.validators || {})
  Object.assign(validators, issuerOptions.validators || {})

  let validationOptions = {}
  Object.assign(validationOptions, options)
  Object.assign(validationOptions, issuerOptions)

  validators.aud(body, audiences, validationOptions)
  validators.iat(body, unixNow, validationOptions)
  validators.nbf(body, unixNow, validationOptions)
  validators.exp(body, unixNow, validationOptions)

  return body
}

function validateNotBefore(body, unixNow, options) {
  if (body.nbf && body.nbf > unixNow + options.nbfIatSkew) {
    throw new JwtVerifyError(
      `Not before in the future by more than ${options.nbfIatSkew} seconds`
    )
  }
}

function validateIssuedAt(body, unixNow, options) {
  if (body.iat && body.iat > unixNow + options.nbfIatSkew) {
    throw new JwtVerifyError(
      `Issued at in the future by more than ${options.nbfIatSkew} seconds`
    )
  }
}

function validateAudience(body, audiences, options) {
  let auds = Array.isArray(body.aud) ? body.aud : [body.aud]
  if (!auds.some(aud => audiences.includes(aud))) {
    throw new JwtVerifyError(`Unknown audience '${auds.join(',')}'`)
  }
}

function validateExpires(body, unixNow, options = {}) {
  if (!body.exp) {
    throw new JwtVerifyError(`No expires set on token`)
  }
  let notBefore = body.iat || body.nbf || unixNow
  if (options.expiresMax && body.exp > notBefore + options.expiresMax) {
    throw new JwtVerifyError(
      `Expires in the future by more than ${options.expiresMax} seconds`
    )
  }
  if (body.exp + (options.expiresSkew || 0) <= unixNow) {
    throw new JwtVerifyError('Token has expired')
  }
}

module.exports = jwtDecode
