export class JwtServiceAuthError extends Error {
 public name: string
 public context: { [key: string]: unknown }
  constructor(message: string, innerError: Record<string, unknown> = {}) {
    super(message)

    this.name = 'JwtServiceAuthError'
    this.context = innerError || null
  }
}
