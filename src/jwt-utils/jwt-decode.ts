import crypto from 'crypto'

import { JwtVerifyError } from '../jwt-verify-error'
import type { PublicKeys } from '../pubkeys-helper'
import { isJwtBody, isJwtHeader, type JwtBody, type JwtHeader } from '../types'
import * as base64UrlSafe from '../utils/base64-urlsafe'
import type { PublicKey } from './decode-validators'
import {
  DecodeValidators,
  type DecodingOptions,
  validateAudience,
  validateExpires,
  validateIssuedAt,
  validateNotBefore
} from './decode-validators'
import { getAlgorithms } from './get-algorithms'

const defaultDecodingOptions: DecodingOptions = {
  expiresSkew: 0,
  expiresMax: 0,
  nbfIatSkew: 300
}

function checkJwt(jwt: { header: unknown; body: unknown }): asserts jwt is { header: JwtHeader; body: JwtBody } {
  if (!isJwtHeader(jwt.header)) {
    throw new JwtVerifyError('Invalid header')
  }

  if (!isJwtBody(jwt.body)) {
    throw new JwtVerifyError('Invalid body')
  }
}

export function decode(
  jwt: string,
  publicKeys: PublicKeys,
  audiences: string[],
  options: DecodingOptions | number = defaultDecodingOptions
): JwtBody {
  if (typeof options === 'number') {
    // Backwards compatibility with old api
    options = {
      ...defaultDecodingOptions,
      nbfIatSkew: options
    }
  }

  const parts = jwt.split(/\./)

  if (parts.length !== 3) {
    throw new JwtVerifyError('JWT does not contain 3 dots')
  }

  const parsedHeader = JSON.parse(base64UrlSafe.decode(parts[0]).toString('utf8')) as unknown
  const parsedBody = JSON.parse(base64UrlSafe.decode(parts[1]).toString('utf8')) as unknown
  const decodedJwt = { header: parsedHeader, body: parsedBody }

  checkJwt(decodedJwt)

  if (options.fixup) {
    options.fixup(decodedJwt.header, decodedJwt.body)
  }

  // Verify the header and body again after fixup
  checkJwt(decodedJwt)

  const { header, body } = decodedJwt
  const { signAlgo, hmacAlgo } = getAlgorithms(header.alg)

  if (signAlgo === null && hmacAlgo === null) {
    throw new JwtVerifyError('Only alg RS256, RS384, RS512, ES256, ES384, ES512, HS256, HS384 and HS512 are supported')
  }

  if (!body.iss) {
    throw new JwtVerifyError('No issuer set')
  }

  const issuer = publicKeys[body.iss]

  if (!issuer) {
    throw new JwtVerifyError(`Unknown issuer '${body.iss}'`)
  }

  // Find public key
  let pubkeyOrSharedKey =
    typeof header.kid === 'string' ? issuer[`${header.kid}@${header.alg}`] : issuer[`default@${header.alg}`]

  let issuerOptions: Partial<PublicKey> = {}

  if (typeof pubkeyOrSharedKey === 'object' && pubkeyOrSharedKey !== null && 'publicKey' in pubkeyOrSharedKey) {
    issuerOptions = pubkeyOrSharedKey
    pubkeyOrSharedKey = pubkeyOrSharedKey.publicKey
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
      throw new JwtVerifyError(`Signature verification failed with algorithm '${header.alg}'`)
    }
  } else if (hmacAlgo) {
    const hmac = crypto.createHmac(hmacAlgo, pubkeyOrSharedKey)
    hmac.update(`${parts[0]}.${parts[1]}`, 'utf8')

    const signatureBuffer = hmac.digest()

    if (!crypto.timingSafeEqual(signatureOrHash, signatureBuffer)) {
      throw new JwtVerifyError(`Verification failed with algorithm '${header.alg}'`)
    }
  } else {
    throw Error('Should never happen')
  }

  const unixNow = Math.floor(Date.now() / 1000)

  const defaultValidators: Required<PublicKey['validators']> = {
    aud: validateAudience,
    exp: validateExpires,
    iat: validateIssuedAt,
    nbf: validateNotBefore
  }

  const validators = { ...defaultValidators, ...issuerOptions.validators, ...options.validators } as DecodeValidators
  const validationOptions: DecodingOptions & Partial<PublicKey> = { ...options, ...issuerOptions }

  validators.aud?.(body, audiences)
  validators.iat?.(body, unixNow, validationOptions)
  validators.nbf?.(body, unixNow, validationOptions)
  validators.exp?.(body, unixNow, validationOptions)

  return body
}
