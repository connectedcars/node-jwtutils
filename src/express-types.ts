import http from 'http'

// We minimally replicate the express types that we need for the
// JwtAuthMiddlewareHandler and tests to avoid depending on express directly

export interface ExpressNextFunction {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (err?: any): void
}

export type ExpressRequest = http.IncomingMessage

export type ExpressResponse = http.ServerResponse
