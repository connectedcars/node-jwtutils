import crypto from 'crypto'

import type { JwtBody, JwtHeader } from '../types'
import * as base64UrlSafe from '../utils/base64-urlsafe'
import { getAlgorithms } from './get-algorithms'

export function encode(
  privateKey: Buffer | string | null,
  header: JwtHeader,
  body: JwtBody,
  privateKeyPassword: string | null = null
): string {
  const { signAlgo, hmacAlgo } = getAlgorithms(header.alg)

  if (signAlgo === null && hmacAlgo === null) {
    throw new Error('Only alg RS256, RS384, RS512, ES256, ES384, ES512, HS256, HS384 and HS512 are supported')
  }

  // Base64 encode header and body
  const headerBase64 = base64UrlSafe.encode(Buffer.from(JSON.stringify(header)))
  const bodyBase64 = base64UrlSafe.encode(Buffer.from(JSON.stringify(body)))
  const headerBodyBase64 = headerBase64 + '.' + bodyBase64

  let signatureBuffer: Buffer

  /* istanbul ignore else */
  if (signAlgo) {
    if (!privateKey) {
      throw new Error(`privateKey can not be null for ${header.alg}`)
    }

    const sign = crypto.createSign(signAlgo)

    // Add header and body of JWT to sign
    sign.update(headerBodyBase64, 'utf8')
    sign.end()

    // Sign with private key
    if (privateKeyPassword !== null) {
      signatureBuffer = sign.sign({
        key: privateKey,
        passphrase: privateKeyPassword
      })
    } else {
      signatureBuffer = sign.sign(privateKey)
    }
  } else if (hmacAlgo) {
    if (!privateKeyPassword) {
      throw new Error(`privateKeyPassword can not be null for ${header.alg}`)
    }

    const hmac = crypto.createHmac(hmacAlgo, privateKeyPassword)
    hmac.update(headerBodyBase64)
    signatureBuffer = hmac.digest()
  } else {
    throw Error(`Should never happen`)
  }

  // Construct final JWT
  const signatureBase64 = base64UrlSafe.encode(signatureBuffer)
  return headerBodyBase64 + '.' + signatureBase64
}
