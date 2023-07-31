export function encode(buffer: Buffer): string {
  return buffer
    .toString('base64')
    .replace(/\+/g, '-') // Convert '+' to '-'
    .replace(/\//g, '_') // Convert '/' to '_'
    .replace(/=+$/, '') // Remove ending '='
}

export function decode(base64StringUrlSafe: string): Buffer {
  let base64String = base64StringUrlSafe.replace(/-/g, '+').replace(/_/g, '/')
  switch (base64String.length % 4) {
    case 2:
      base64String += '=='
      break
    case 3:
      base64String += '='
      break
  }
  return Buffer.from(base64String, 'base64')
}

