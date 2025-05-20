import { JwtVerifyError } from '../jwt-verify-error'
import type { JwtBody, JwtHeader } from '../types'

export type Fixup = (header: JwtHeader, body: JwtBody) => void

export interface DecodeValidators {
  aud?: typeof validateAudience
  exp?: typeof validateExpires
  iat?: typeof validateIssuedAt
  nbf?: typeof validateNotBefore
}

export interface DecodingOptions {
  expiresSkew?: number
  expiresMax?: number
  nbfIatSkew?: number
  fixup?: Fixup
  validators?: DecodeValidators
}

export interface PublicKey {
  publicKey: string
  expiresSkew?: number
  expiresMax?: number
  validators?: DecodeValidators
}

export type ValidatorOptions = DecodingOptions & Partial<PublicKey>

export function validateNotBefore(body: JwtBody, unixNow: number, options: ValidatorOptions): void | never {
  if (options.nbfIatSkew && body.nbf && body.nbf > unixNow + options.nbfIatSkew) {
    throw new JwtVerifyError(`Not before in the future by more than ${options.nbfIatSkew} seconds`)
  }
}

export function validateIssuedAt(body: JwtBody, unixNow: number, options: ValidatorOptions): void | never {
  if (options.nbfIatSkew && body.iat && body.iat > unixNow + options.nbfIatSkew) {
    throw new JwtVerifyError(`Issued at in the future by more than ${options.nbfIatSkew} seconds`)
  }
}

export function validateAudience(body: JwtBody, audiences: string[]): void | never {
  const auds = (Array.isArray(body.aud) ? body.aud : [body.aud]) as string[]

  if (!auds.some(aud => audiences.includes(aud))) {
    throw new JwtVerifyError(`Unknown audience '${auds.join(',')}'`)
  }
}

export function validateExpires(body: JwtBody, unixNow: number, options: ValidatorOptions): void | never {
  if (!body.exp) {
    throw new JwtVerifyError('No expires set on token')
  }

  const notBefore = body.iat || body.nbf || unixNow

  if (options.expiresMax && body.exp && body.exp > notBefore + options.expiresMax) {
    throw new JwtVerifyError(`Expires in the future by more than ${options.expiresMax} seconds`)
  }

  if (body.exp && body.exp + (options.expiresSkew || 0) <= unixNow) {
    throw new JwtVerifyError('Token has expired')
  }
}
