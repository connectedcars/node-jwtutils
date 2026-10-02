/**
 * @property signAlgo Signing algorithm
 * @property hmacAlgo HMAC (hash-based message authentication code) algorithm
 * @property canStream True if the algorithm supports the crypto module stream (.update) api
 * @property algorithmFromKey True if the algorithm is automatically derived from
 *                            the private key (true for e.g. ed25519)
 */
export interface AlgorithmSpec {
  signAlgo: string | null
  hmacAlgo: string | null
  canStream: boolean | null
  algorithmFromKey: boolean | null
}

export function getAlgorithms(alg?: string | null): AlgorithmSpec {
  let signAlgo = null
  let hmacAlgo = null
  let canStream = true
  let algorithmFromKey = false

  switch (alg) {
    case 'RS256': {
      signAlgo = 'RSA-SHA256'
      break
    }
    case 'RS384': {
      signAlgo = 'RSA-SHA384'
      break
    }
    case 'RS512': {
      signAlgo = 'RSA-SHA512'
      break
    }
    case 'ES256': {
      signAlgo = 'sha256'
      break
    }
    case 'ES384': {
      signAlgo = 'sha384'
      break
    }
    case 'ES512': {
      signAlgo = 'sha512'
      break
    }
    case 'Ed25519': {
      // SHA-512 is used but automatically derived from the private key. This
      // is just set to signal that the function returns valid values
      signAlgo = 'sha512'
      canStream = false
      algorithmFromKey = true
      break
    }
    case 'HS256': {
      hmacAlgo = 'sha256'
      break
    }
    case 'HS384': {
      hmacAlgo = 'sha384'
      break
    }
    case 'HS512': {
      hmacAlgo = 'sha512'
      break
    }
    default: {
      break
    }
  }

  return {
    signAlgo,
    hmacAlgo,
    canStream: signAlgo || hmacAlgo ? canStream : null,
    algorithmFromKey: signAlgo || hmacAlgo ? algorithmFromKey : null
  }
}
