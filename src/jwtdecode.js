'use strict'

const crypto = require('crypto')

const base64UrlSafe = require('./base64urlsafe')
const JwtVerifyError = require('./jwtverifyerror')

function jwtDecode(jwt, publicKeys, audiences, nbfIatSkrew = 300) {
  if (typeof jwt !== 'string') {
    throw new Error('jwt needs to a string')
  }

  if (typeof publicKeys !== 'object' || Array.isArray(publicKeys)) {
    throw new Error(
      'publicKeys needs to be a map of { issuer: { keyid: "PEM encoded key" }'
    )
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
    throw new JwtVerifyError('Unknown issuer')
  }

  let signature = base64UrlSafe.decode(parts[2])

  const verifier = crypto.createVerify(algo)
  verifier.write(`${parts[0]}.${parts[1]}`, 'utf8')
  verifier.end()

  let pubkey = header.kid
    ? issuer[`${header.kid}@${header.alg}`]
    : issuer[`default@${header.alg}`]
  if (!pubkey) {
    throw new JwtVerifyError('Unknown pubkey id for this issuer')
  }

  if (!verifier.verify(pubkey, signature)) {
    throw new JwtVerifyError(
      `Signature verification failed with alg ${header.alg}`
    )
  }

  let auds = Array.isArray(body.aud) ? body.aud : [body.aud]
  if (!auds.some(aud => audiences.includes(aud))) {
    throw new JwtVerifyError('Unknown audience')
  }

  let unixNow = Math.floor(Date.now() / 1000)

  if (body.iat && body.iat > unixNow + nbfIatSkrew) {
    throw new JwtVerifyError(
      `Issued at in the future by more than ${nbfIatSkrew} seconds`
    )
  }

  if (body.nbf && body.nbf > unixNow + nbfIatSkrew) {
    throw new JwtVerifyError(
      `Not before in the future by more than ${nbfIatSkrew} seconds`
    )
  }

  if (!body.exp) {
    throw new JwtVerifyError(`No expires set on token`)
  }

  if (body.exp <= unixNow) {
    throw new JwtVerifyError('Token has expired')
  }

  return body
}

module.exports = jwtDecode
