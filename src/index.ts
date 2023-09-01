import * as JwkUtils from './jwkutils'
import * as JwtUtils from './jwt-utils'
import { JwtAuthMiddleware } from './jwtauthmiddleware'
import { JwtServiceAuth } from './jwtserviceauth'
import { JwtServiceAuthError } from './jwtserviceautherror'
import { JwtVerifyError } from './jwtverifyerror'
import { PubkeysHelper } from './pubkeyshelper'

export { JwkUtils, JwtAuthMiddleware, JwtServiceAuth, JwtServiceAuthError, JwtUtils, JwtVerifyError, PubkeysHelper }

// This is defined in auth api
export interface JwtBody {
  iss: string // Issuing authority of this token, i.e. our identity provider
  ons: string // Organization namespace this token is issued within
  sub: string // Identifier for the party this token is issued on behalf of
  aud: string // Target audience for this token, i.e. our applications
  acr: string // The level of authentication, i.e. AM1
  jti: string // Unique id for this token
  sid: string // Unique id for this session
  amr: string[] // Access methods used to obtain this token, can be a combination, i.e. password and sms otp
  exp: number // Timestamp for expiry
  iat: number // Timestamp for issuing date
  nbf: number // Timestamp which this token should not be used before
  clt: number // Current life time counting number of refresshes in this session
  email?: string
  email_verified?: boolean
}

export interface RevokedToken {
  id?: number | string
  jti: string
  revokedAt: Date
}

export interface PublicKey {
  publicKey: string
  expiresSkew?: number
  expiresMax?: number
  validators?: Record<string, () => boolean>
}
