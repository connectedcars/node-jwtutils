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
  typ?: string
  alg?: string
  kid?: string // Not mentioned in the RFC spec
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
 * @property clt            Current life time counting number of refresshes in this session
 * @property email          End-User's preferred e-mail address
 * @property email_verified True if the End-User's e-mail address has been verified; otherwise false
 */
export interface JwtBody {
  iss?: string
  ons?: string
  sub?: string
  aud?: string | string[]
  acr?: string
  jti?: string
  sid?: string
  amr?: string[]
  exp?: number
  iat?: number
  nbf?: number
  clt?: number
  email?: string
  email_verified?: boolean

  // NOTE: According to the specs, this is a space-separated list of scopes but
  // is also used in this package as an array as well
  scope?: string | string[]
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
  kid?: string
  kty: string
  use?: string
  alg?: string
  e?: string
  n?: string
  crv?: string
  x?: string
  y?: string
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

  if ('typ' in obj && typeof obj.typ !== 'string') {
    return false
  }

  if ('alg' in obj && typeof obj.alg !== 'string') {
    return false
  }

  if ('kid' in obj && typeof obj.kid !== 'string') {
    return false
  }

  return true
}

export function isJwtBody(obj: unknown): obj is JwtBody {
  if (obj === null || typeof obj !== 'object') {
    return false
  }

  if ('iss' in obj && typeof obj.iss !== 'string') {
    return false
  }

  if ('ons' in obj && typeof obj.ons !== 'string') {
    return false
  }

  if ('sub' in obj && typeof obj.sub !== 'string') {
    return false
  }

  if ('aud' in obj && typeof obj.aud !== 'string' && !isArrayOfType<string>(obj.aud, 'string')) {
    return false
  }

  if ('acr' in obj && typeof obj.acr !== 'string') {
    return false
  }

  if ('jti' in obj && typeof obj.jti !== 'string') {
    return false
  }

  if ('sid' in obj && typeof obj.sid !== 'string') {
    return false
  }

  if ('amr' in obj && !isArrayOfType<string>(obj.amr, 'string')) {
    return false
  }

  if ('exp' in obj && typeof obj.exp !== 'number') {
    return false
  }

  if ('iat' in obj && typeof obj.iat !== 'number') {
    return false
  }

  if ('nbf' in obj && typeof obj.nbf !== 'number') {
    return false
  }

  if ('clt' in obj && typeof obj.clt !== 'number') {
    return false
  }

  if ('email' in obj && typeof obj.email !== 'string') {
    return false
  }

  if ('email_verified' in obj && typeof obj.email_verified !== 'boolean') {
    return false
  }

  if ('scope' in obj && typeof obj.scope !== 'string' && !isArrayOfType<string>(obj.scope, 'string')) {
    return false
  }

  return true
}

export function isJwkBody(obj: unknown): obj is JwkBody {
  if (obj === null || typeof obj !== 'object') {
    return false
  }

  if ('kid' in obj && typeof obj.kid !== 'string') {
    return false
  }

  if ('kty' in obj && typeof obj.kty !== 'string') {
    return false
  }

  if ('use' in obj && typeof obj.use !== 'string') {
    return false
  }

  if ('alg' in obj && typeof obj.alg !== 'string') {
    return false
  }

  if ('e' in obj && typeof obj.e !== 'string') {
    return false
  }

  if ('n' in obj && typeof obj.n !== 'string') {
    return false
  }

  if ('crv' in obj && typeof obj.crv !== 'string') {
    return false
  }

  if ('x' in obj && typeof obj.x !== 'string') {
    return false
  }

  if ('y' in obj && typeof obj.y !== 'string') {
    return false
  }

  return true
}
