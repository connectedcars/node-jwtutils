export function getAlgorithms(alg?: string | null): { signAlgo: string | null; hmacAlgo: string | null } {
  let signAlgo = null
  let hmacAlgo = null

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

  return { signAlgo, hmacAlgo }
}
