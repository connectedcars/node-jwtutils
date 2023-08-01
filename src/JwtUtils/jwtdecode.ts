import crypto from 'crypto'

import * as base64UrlSafe from '../base64urlsafe'
import { JwtVerifyError } from '../jwtverifyerror'

const defaultOptions = {
  expiresSkew: 0,
  expiresMax: 0,
  nbfIatSkew: 300,
  fixup: null
}

export interface JwtBody {
  iss: string // Issuing authority of this token, i.e. our identity provider
  ons?: string // Organization namespace this token is issued within
  sub?: string // Identifier for the party this token is issued on behalf of
  aud: string | string[] // Target audience for this token, i.e. our applications
  acr?: string // The level of authentication, i.e. AM1
  jti?: string // Unique id for this token
  sid?: string // Unique id for this session
  amr?: string[] // Access methods used to obtain this token, can be a combination, i.e. password and sms otp
  exp: number // Timestamp for expiry
  iat: number // Timestamp for issuing date
  nbf?: number // Timestamp which this token should not be used before
  clt?: number // Current life time counting number of refresshes in this session
  email?: string
  email_verified?: boolean
}

export function decode(
  jwt: string,
  publicKeys: Record<string, Record<string, unknown>>,
  audiences: string[],
  options: Record<any, unknown> = defaultOptions
): JwtBody {
  if (typeof options === 'number') {
    // Backwards compatibility with old api
    options = {
      ...defaultOptions,
      nbfIatSkew: options
    }
  }

  if (typeof options !== 'object' || Array.isArray(publicKeys)) {
    throw new Error('options needs to a map of { nbfIatSkew: 300, ... }')
  }

  const parts = jwt.split(/\./)
  if (parts.length !== 3) {
    throw new JwtVerifyError('JWT does not contain 3 dots')
  }

  const header = JSON.parse(base64UrlSafe.decode(parts[0]).toString('utf8'))
  const body = JSON.parse(base64UrlSafe.decode(parts[1]).toString('utf8'))
  if (typeof options.fixup === 'function') {
    options.fixup(header, body)
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
      throw new JwtVerifyError(
        'Only alg RS256, RS384, RS512, ES256, ES384, ES512, HS256, HS384 and HS512 are supported'
      )
  }

  if (!body.iss) {
    throw new JwtVerifyError('No issuer set')
  }

  const issuer = publicKeys[body.iss]
  if (!issuer) {
    throw new JwtVerifyError(`Unknown issuer '${body.iss}'`)
  }

  // Find public key
  //todo: grace find better way to handle this
  let pubkeyOrSharedKey =
    typeof header.kid === 'string'
      ? (issuer[`${header.kid}@${header.alg}`] as string)
      : (issuer[`default@${header.alg}`] as string)

  let issuerOptions: Record<string, unknown> = {}
  if (typeof pubkeyOrSharedKey === 'object' && pubkeyOrSharedKey !== null && pubkeyOrSharedKey['publicKey']) {
    issuerOptions = pubkeyOrSharedKey
    pubkeyOrSharedKey = pubkeyOrSharedKey['publicKey']
  }

  if (!pubkeyOrSharedKey) {
    throw new JwtVerifyError(`Unknown pubkey id '${header.kid}' for this issuer`)
  }

  const signatureOrHash = base64UrlSafe.decode(parts[2])
  /* istanbul ignore else */
  if (signAlgo) {
    // Validate signature
    const verifier = crypto.createVerify(signAlgo)
    verifier.write(`${parts[0]}.${parts[1]}`, 'utf8')
    verifier.end()
    if (!verifier.verify(pubkeyOrSharedKey, signatureOrHash)) {
      throw new JwtVerifyError(`Signature verification failed with alg '${header.alg}'`)
    }
  } else if (hmacAlgo) {
    const hmac = crypto.createHmac(hmacAlgo, pubkeyOrSharedKey)
    hmac.update(`${parts[0]}.${parts[1]}`, 'utf8')
    const signatureBuffer = hmac.digest()
    if (!crypto.timingSafeEqual(signatureOrHash, signatureBuffer)) {
      throw new JwtVerifyError(`Verification failed with alg '${header.alg}'`)
    }
  } else {
    throw Error(`Should never happen`)
  }

  const unixNow = Math.floor(Date.now() / 1000)
  const validators = {
    aud: validateAudience,
    exp: validateExpires,
    iat: validateIssuedAt,
    nbf: validateNotBefore
  }
  Object.assign(validators, options.validators || {})
  Object.assign(validators, issuerOptions.validators || {})

  const validationOptions = {}
  Object.assign(validationOptions, options)
  Object.assign(validationOptions, issuerOptions)

  validators.aud(body, audiences)
  validators.iat(body, unixNow, validationOptions)
  validators.nbf(body, unixNow, validationOptions)
  validators.exp(body, unixNow, validationOptions)

  return body
}

function validateNotBefore(body: Record<string, unknown>, unixNow: number, options: Record<string, unknown>): void {
  if (typeof options.nbfIatSkew === 'number') {
    if (body.nbf && body.nbf > unixNow + options.nbfIatSkew) {
      throw new JwtVerifyError(`Not before in the future by more than ${options.nbfIatSkew} seconds`)
    }
  }
}

function validateIssuedAt(body: Record<string, unknown>, unixNow: number, options: Record<string, unknown>): void {
  if (typeof options.nbfIatSkew === 'number') {
    if (body.iat && body.iat > unixNow + options.nbfIatSkew) {
      throw new JwtVerifyError(`Issued at in the future by more than ${options.nbfIatSkew} seconds`)
    }
  }
}

function validateAudience(body: Record<string, unknown>, audiences: string[]): void {
  const auds = Array.isArray(body.aud) ? body.aud : [body.aud]
  if (!auds.some(aud => audiences.includes(aud))) {
    throw new JwtVerifyError(`Unknown audience '${auds.join(',')}'`)
  }
}

function validateExpires(body: Record<string, unknown>, unixNow: number, options: Record<string, unknown>) {
  if (!body.exp) {
    throw new JwtVerifyError(`No expires set on token`)
  }
  const notBefore = body.iat || body.nbf || unixNow
  if (options.expiresMax) {
    if (typeof notBefore === 'number' && typeof options.expiresMax === 'number') {
      if (options.expiresMax && body.exp > notBefore + options.expiresMax) {
        throw new JwtVerifyError(`Expires in the future by more than ${options.expiresMax} seconds`)
      }
    } else {
      throw new JwtVerifyError('body.iat || body.nbf || options.expiresMax is unknown type')
    }
  }

  if (typeof body.exp === 'number' && typeof options.expiresSkew === 'number') {
    if (body.exp + (options.expiresSkew || 0) <= unixNow) {
      throw new JwtVerifyError('Token has expired')
    }
  } else {
    throw new JwtVerifyError('body.exp is unknown type')
  }
}
