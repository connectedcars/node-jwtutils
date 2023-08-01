// SEQUENCE(OBJECT IDENTIFIER = 1.2.840.113549.1.1.1, NULL) - rsaEncryption
const rsaPublicKeyOid = [0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05, 0x00]

// OBJECT IDENTIFIER=1.2.840.10045.2.1 - ecPublicKey
const ecPublicKeyOid = [0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]
const secp256k1Oid = [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a] // OBJECT IDENTIFIER=1.3.132.0.10) - secp256k1
const prime256v1Oid = [
  //  OBJECT IDENTIFIER=1.2.840.10045.3.1.7 - prime256v1
  0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07
]
const secp384r1Oid = [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22] // OBJECT IDENTIFIER=1.3.132.0.34 - secp384r1
const secp521r1Oid = [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23] // OBJECT IDENTIFIER=1.3.132.0.35 - secp521r1

export function jwkToPem(jwk: Record<string, string>): string {
  switch (jwk.kty) {
    case 'RSA': {
      return rsaPublicJwkToPem(jwk)
    }
    case 'EC': {
      return ecPublicKeyJwkToPem(jwk)
    }
    default: {
      throw new Error(`Unknown key type: ${jwk.kty}`)
    }
  }
}

export function rsaPublicJwkToPem(rsaPublicKeyJwk: Record<string, string>): string {
  const modulusBytes = asn1PositiveInteger(new Uint8Array(Buffer.from(rsaPublicKeyJwk.n, 'base64')))
  const exponentBytes = asn1PositiveInteger(new Uint8Array(Buffer.from(rsaPublicKeyJwk.e, 'base64')))

  const integerSequenceBytes = encodeAsn1Bytes(0x30, [
    ...modulusBytes, // modulus
    ...exponentBytes // exponent
  ])

  const bitStringBytes = encodeAsn1Bytes(
    0x03,
    // Sequence
    [0x00, ...integerSequenceBytes]
  )

  const pemBytes = new Uint8Array(
    encodeAsn1Bytes(0x30, [
      // Header
      ...rsaPublicKeyOid,
      // Bit string
      ...bitStringBytes
    ])
  )

  return formatPemPublicKey(pemBytes)
}

export function ecPublicKeyJwkToPem(ecPublicKeyJwk: Record<string, string>): string {
  let keyOid
  switch (ecPublicKeyJwk.crv) {
    case 'K-256': {
      // Not part of the JWK standard
      keyOid = encodeAsn1Bytes(0x30, [...ecPublicKeyOid, ...secp256k1Oid])
      break
    }
    case 'P-256': {
      keyOid = encodeAsn1Bytes(0x30, [...ecPublicKeyOid, ...prime256v1Oid])
      break
    }
    case 'P-384': {
      keyOid = encodeAsn1Bytes(0x30, [...ecPublicKeyOid, ...secp384r1Oid])
      break
    }
    case 'P-521': {
      keyOid = encodeAsn1Bytes(0x30, [...ecPublicKeyOid, ...secp521r1Oid])
      break
    }
    default: {
      throw new Error(`Unknown curve ${ecPublicKeyJwk.crv}`)
    }
  }

  const xBytes = new Uint8Array(Buffer.from(ecPublicKeyJwk.x, 'base64'))
  const yBytes = new Uint8Array(Buffer.from(ecPublicKeyJwk.y, 'base64'))

  const bitStringBytes = encodeAsn1Bytes(
    0x03,
    // Sequence
    [0x00, 0x04, ...xBytes, ...yBytes]
  )

  const pemBytes = new Uint8Array(
    encodeAsn1Bytes(0x30, [
      // Header
      ...keyOid,
      // Bit string
      ...bitStringBytes
    ])
  )

  return formatPemPublicKey(pemBytes)
}

export function encodeAsn1Bytes(type: number, bytes: Uint8Array | number[]): Uint8Array | number[] {
  let lengthBytes: number[]
  if (bytes.length === 0) {
    lengthBytes = [0]
  } else if (bytes.length < 0x80) {
    lengthBytes = [bytes.length]
  } else if (bytes.length <= 0xff) {
    lengthBytes = [0x81, bytes.length & 0xff]
  } else if (bytes.length <= 0xffff) {
    lengthBytes = [0x82, bytes.length >> 8, bytes.length & 0xff]
  } else if (bytes.length <= 0xffffff) {
    lengthBytes = [0x83, 0xff0000 >> 16, bytes.length >> 8, bytes.length & 0xff]
  } else {
    lengthBytes = [0x84, 0xff000000 >> 24, 0xff0000 >> 16, bytes.length >> 8, bytes.length & 0xff]
  }
  return [type, ...lengthBytes, ...bytes]
}

export function asn1PositiveInteger(bytes: Uint8Array | number[]): Uint8Array | number[] {
  if (bytes[0] > 0x7f) {
    return encodeAsn1Bytes(0x02, [0x00, ...bytes])
  }
  return encodeAsn1Bytes(0x02, bytes)
}

export function formatPemPublicKey(bytes: Uint8Array): string {
  const pemBase64 = Buffer.from(bytes.buffer)
    .toString('base64')
    .match(/.{1,64}/g)
    .join('\n')
  return `-----BEGIN PUBLIC KEY-----\n${pemBase64}\n-----END PUBLIC KEY-----`
}

// export function hexDump(bytes) {
//   console.log(
//     Buffer.from(bytes)
//       .toString('hex')
//       .toUpperCase()
//       .match(/.{1,32}/g)
//       .join('\n')
//       .replace(/(\w\w)/g, '$1 ')
//       .replace(/\s$/, '')
//   )
// }

// Links
// * https://github.com/jrnker/CSharp-easy-RSA-PEM/blob/48349cfc010d6c6acf9feb12282431d9d03fd28c/CSharp-easy-RSA-PEM/CSharp-easy-RSA-PEM/AsnKeyBuilder.cs
// * https://lapo.it/asn1js/
// * https://github.com/EternalDeiwos/keyto/tree/d8480710393bc9ed93be3758a30246cddedec771
