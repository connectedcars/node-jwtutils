import * as JwkUtils from './jwkutils'
import * as JwtUtils from './jwt-utils'
import { JwtAuthMiddleware } from './jwtauthmiddleware'
import { JwtServiceAuth } from './jwtserviceauth'
import { JwtServiceAuthError } from './jwtserviceautherror'
import { JwtVerifyError } from './jwtverifyerror'
import { PubkeysHelper } from './pubkeyshelper'

export { JwkUtils, JwtAuthMiddleware, JwtServiceAuth, JwtServiceAuthError, JwtUtils, JwtVerifyError, PubkeysHelper }

export interface RevokedToken {
  id?: number | string
  jti: string
  revokedAt: Date
}

export interface PublicKey {
  publicKey: string
  expiresSkew?: number
  expiresMax?: number
  // eslint-disable-next-line @typescript-eslint/ban-types
  validators?: Record<string, Function>
}
