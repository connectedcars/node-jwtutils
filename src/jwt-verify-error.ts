export class JwtVerifyError extends Error {
  public readonly name: string
  public readonly innerError: Error | null

  public constructor(message: string, innerError: Error | null = null) {
    super(message)

    this.name = 'JwtVerifyError'
    this.innerError = innerError
  }
}
