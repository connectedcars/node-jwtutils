/**
 * A JSON Web Token header
 *
 * RFC source: https://www.rfc-editor.org/rfc/rfc7519
 *
 * @property typ The type of the token (usually 'JWT')
 * @property alg Signing algorithm used
 * @property kid Key ID parameter which is used to match a specific key
 */
export interface JwtHeader {
  typ?: string | null
  alg?: string | null
  // Not mentioned in the RFC spec but mentioned here: https://www.rfc-editor.org/rfc/rfc7515#section-4.1.4
  kid?: string | null
}

/**
 * A JSON Web Token body
 *
 * The fields are a combination of the following specs:
 *
 * RFC: https://www.rfc-editor.org/rfc/rfc7519
 * OpenID: https://openid.net/specs/openid-connect-core-1_0.html
 * OAuth 2.0: https://www.rfc-editor.org/rfc/rfc6749.html
 * OpenID Connect Front-Channel Logout 1.0: https://openid.net/specs/openid-connect-frontchannel-1_0.html
 *
 * @property iss            Issuing authority of this token, i.e. our identity provider
 * @property ons            Organization namespace this token is issued within
 * @property sub            Identifier for the party this token is issued on behalf of
 * @property aud            Target audience for this token, i.e. our applications
 * @property acr            The level of authentication, i.e. AM1
 * @property jti            Unique id for this token
 * @property sid            Unique id for this session
 * @property amr            Access methods used to obtain this token, can be a combination, i.e. password and sms otp
 * @property exp            Timestamp for expiry
 * @property iat            Timestamp for issuing date
 * @property nbf            Timestamp which this token should not be used before
 * @property clt            Current life time counting number of refreshes in this session
 * @property email          End-User's preferred e-mail address
 * @property email_verified True if the End-User's e-mail address has been verified; otherwise false
 */
export interface JwtBody {
  iss?: string | null
  ons?: string | null
  sub?: string | null
  aud?: string | string[] | null
  acr?: string | null
  jti?: string | null
  sid?: string | null
  amr?: string[] | null
  exp?: number | null
  iat?: number | null
  nbf?: number | null
  clt?: number | null
  email?: string | null
  email_verified?: boolean | null

  // NOTE: According to the specs, this is a space-separated list of scopes but
  // is also used in this package as an array as well
  scope?: string | string[] | null
}

/**
 * A JSON Web Key (does not contain all fields mentioned in the RFC)
 *
 * RFC source: https://www.rfc-editor.org/rfc/rfc7517
 *
 * @property kid Key ID parameter which is used to match a specific key
 * @property kty Key Type parameter which identifies the cryptographic algorithm family used with the key, such as "RSA" or "EC"
 * @property use Public Key Use parameter which identifies the intended use of the public key (e.g. encrypting, verifying etc.)
 * @property alg Algorithm parameter which identifies the algorithm intended for use with the key
 * @property e   Public exponent for RSA Key blinding operations
 * @property n   Modulus component for RSA Key blinding operations
 * @property crv Curve parameter for elliptic curve keys
 * @property x   Base64-encoded x coordinate for elliptic curve keys
 * @property y   Base64-encoded y coordinate for elliptic curve keys
 */
export interface JwkBody {
  kid?: string | null
  kty: string
  use?: string | null
  alg?: string | null
  e?: string | null
  n?: string | null
  crv?: string | null
  x?: string | null
  y?: string | null
}

function isArrayOfType<T>(obj: unknown, type: string): obj is T[] {
  if (!Array.isArray(obj)) {
    return false
  }

  for (const item of obj) {
    if (typeof item !== type) {
      return false
    }
  }

  return true
}

export function isJwtHeader(obj: unknown): obj is JwtHeader {
  if (obj === null || typeof obj !== 'object') {
    return false
  }

  if ('typ' in obj && obj.typ != null && typeof obj.typ !== 'string') {
    return false
  }

  if ('alg' in obj && obj.alg != null && typeof obj.alg !== 'string') {
    return false
  }

  if ('kid' in obj && obj.kid != null && typeof obj.kid !== 'string') {
    return false
  }

  return true
}

export function isJwtBody(obj: unknown): obj is JwtBody {
  if (obj === null || typeof obj !== 'object') {
    return false
  }

  if ('iss' in obj && obj.iss != null && typeof obj.iss !== 'string') {
    return false
  }

  if ('ons' in obj && obj.ons != null && typeof obj.ons !== 'string') {
    return false
  }

  if ('sub' in obj && obj.sub != null && typeof obj.sub !== 'string') {
    return false
  }

  if ('aud' in obj && obj.aud != null && typeof obj.aud !== 'string' && !isArrayOfType<string>(obj.aud, 'string')) {
    return false
  }

  if ('acr' in obj && obj.acr != null && typeof obj.acr !== 'string') {
    return false
  }

  if ('jti' in obj && obj.jti != null && typeof obj.jti !== 'string') {
    return false
  }

  if ('sid' in obj && obj.sid != null && typeof obj.sid !== 'string') {
    return false
  }

  if ('amr' in obj && obj.amr != null && !isArrayOfType<string>(obj.amr, 'string')) {
    return false
  }

  if ('exp' in obj && obj.exp != null && typeof obj.exp !== 'number') {
    return false
  }

  if ('iat' in obj && obj.iat != null && typeof obj.iat !== 'number') {
    return false
  }

  if ('nbf' in obj && obj.nbf != null && typeof obj.nbf !== 'number') {
    return false
  }

  if ('clt' in obj && obj.clt != null && typeof obj.clt !== 'number') {
    return false
  }

  if ('email' in obj && obj.email != null && typeof obj.email !== 'string') {
    return false
  }

  if ('email_verified' in obj && obj.email_verified != null && typeof obj.email_verified !== 'boolean') {
    return false
  }

  if (
    'scope' in obj &&
    obj.scope != null &&
    typeof obj.scope !== 'string' &&
    !isArrayOfType<string>(obj.scope, 'string')
  ) {
    return false
  }

  return true
}

export function isJwkBody(obj: unknown): obj is JwkBody {
  if (obj === null || typeof obj !== 'object') {
    return false
  }

  if ('kid' in obj && obj.kid != null && typeof obj.kid !== 'string') {
    return false
  }

  if (!('kty' in obj) || typeof obj.kty !== 'string') {
    return false
  }

  if ('use' in obj && obj.use != null && typeof obj.use !== 'string') {
    return false
  }

  if ('alg' in obj && obj.alg != null && typeof obj.alg !== 'string') {
    return false
  }

  if ('e' in obj && obj.e != null && typeof obj.e !== 'string') {
    return false
  }

  if ('n' in obj && obj.n != null && typeof obj.n !== 'string') {
    return false
  }

  if ('crv' in obj && obj.crv != null && typeof obj.crv !== 'string') {
    return false
  }

  if ('x' in obj && obj.x != null && typeof obj.x !== 'string') {
    return false
  }

  if ('y' in obj && obj.y != null && typeof obj.y !== 'string') {
    return false
  }

  return true
}
