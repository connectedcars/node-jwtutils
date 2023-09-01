export class JwtVerifyError extends Error {
  public name: string
  public context: { [key: string]: unknown }
  public constructor(message: string, context: Record<string, unknown> = {}) {
    super(message)

    this.name = 'JwtVerifyError'
    this.context = context || null
  }
}
