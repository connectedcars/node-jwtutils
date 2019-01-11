import { JwkUtils } from "@connectedcars/jwtutils";

// $ExpectType string
JwkUtils.jwkToPem({
  kty: 'RSA',
  n: '12345',
  e: '12345'
})
