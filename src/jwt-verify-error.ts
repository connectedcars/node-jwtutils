export class JwtVerifyError extends Error {
  public readonly name: string
  public readonly context: Record<string, unknown>

  public constructor(message: string, context: Record<string, unknown> = {}) {
    super(message)

    this.name = 'JwtVerifyError'
    this.context = context || null
  }
}
