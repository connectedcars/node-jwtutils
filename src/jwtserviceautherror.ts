// export function JwtServiceAuthError(message: any, innerError: any): void {
//   this.name = 'JwtServiceAuthError'
//   this.message = message
//   this.stack = new Error().stack
//   this.innerError = innerError || null
// }
// JwtServiceAuthError.prototype = Object.create(Error.prototype)
// JwtServiceAuthError.prototype.constructor = JwtServiceAuthError

export class JwtServiceAuthError extends Error {
 public name: string
 public context: { [key: string]: unknown }
  constructor(message: string, innerError: Record<string, unknown> = {}) {
    super(message)

    this.name = 'JwtServiceAuthError'
    this.context = innerError || null
  }
}
