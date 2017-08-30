'use strict'

const Benchmark = require('benchmark')
const jwtUtils = require('./src/index')

const rsaPrivateKeyEncrypted =
  '-----BEGIN RSA PRIVATE KEY-----\n' +
  'Proc-Type: 4,ENCRYPTED\n' +
  'DEK-Info: AES-256-CBC,F8DFFBFC89ACC93CC604E18608B412C4\n' +
  '\n' +
  'UUGCEuSDg8xiy504WKQ4Fg9Xeen1JYxhhO/3vEjfjSgaSf7e3LJWv6jp5KQTfRD5\n' +
  '5lfTI1mHt7NqEziUc5ERq3ueO5x0qtoLNaIsXwXu0/0ex98pjVz6KHnwCB3UqbhZ\n' +
  'PJsyfjdA0dyTUjGZZApDRqbK3FedRHL980VknX+r2LMskYEtY0YZiHurRLt8U0Ph\n' +
  'q9G2LaNwddZzTTCRVSISl1zYLeMrNk7Tdfkwctlhd1a4RKAe8ymXHinE00nMXbio\n' +
  'fJvvCMzPFGvvaRJVKWLyxerZ0Weh0oGXftAgICvOz7AiajQbs7qLBV92I+VPlvQw\n' +
  '515VuZYqupTkGoc5SQhBSzMGBS+kJa5/+IrNx/pjEUc9m4sb2Pr9IXbPFrZhtyAR\n' +
  'JeYxx2keodFeg/sM0GQWUM0yt807DoQflnLa/hVFI9/OzpfHhe4ToaoLNVCAez2L\n' +
  'pAB4HDgu0AbTyt+ffx3yQwfLZHsa90V/+cr1/AXlYUSHu3rSar2WSNpeWsUDsebe\n' +
  '0nQeu7w/WZt0v9l1Cz6s30GpdYQNuPoqLl+66mgAY9eUmvg7JpHnfCllpTiox0Mo\n' +
  'LmkQSyjZNjmBLX4cr9TAUpXTR7CwGMCw1fv/PDhVabxDQebH52aPOILV6Fo4Mqho\n' +
  'ZQ07SdsybKXyoVahOWdxAMfgKt8H3hApCJqDCrvuIur1CXtUCMiG5yNmOM2RuBpr\n' +
  'WFY7ofqJtKGSP90m3FZRFdP7iL1MM4iZ3WOFyTby//NLQvSVNfCU209DzpACQ/BI\n' +
  'CHUJLSJG8rA4HZKqViqqZP54iCZRw48jH+jeNP7+z8BLHfs2MN3x21EolIh0l2BO\n' +
  'awExA8/8HcZGb0ERsInwD3Rh7px8oGy9A6vd6sxaCEr1CmKCKrayyqPga6mRNDUD\n' +
  'rJZ00eyV76VuG9+SryBrf9iUF6iahLC2+RkQrKh1dVElsHS6a3OAoJHgZGbEH0g7\n' +
  'BpozW7gljjlin0C+SgfDYJpsCbYMwf/SjtG8EJ0Q0t9SAhBpBDDcTCLY9q5j2gFU\n' +
  '0wA6fVsdobWsfzZWd8RDVAiIGDwk9KTeV27+YKrwmyAxXn+82zZyePT/oMmjuqCL\n' +
  'W62K8rXqMXsSdUXMJWKtHIliigtcBw9XZNK8puP0M2xq0UMu4rlQ4dlyNBYHgQSi\n' +
  'zqR+KqnKARPY9l+/T2JrapCn7h+4ycTRV8X39XKWXZY2KARinTg7elR6GMZccuum\n' +
  'B6QG4fTUPfyy7i7m6Vl2QT++/npnQYR56Hns3KLjnozu0oSxj7qXQdqNBa4Y48CX\n' +
  'ByNAZM2QUWus41GYZRjEux4QjnSvtOCOA9auQN27I/oDjVjKG1fv/lnGSvCEctxz\n' +
  '8oHI8k2cRUXwm+tJh+HMrLnMGKdt09WAutjEU4fQJQX8YOTpNelNScTXKF0nwxOD\n' +
  'UvYNdLs/uC9ai2GBOqO6Wz6FSQFDp58PEl2G+4GQiQ8bveAbzIpxyu8gZvNRxuyM\n' +
  'ClA5F7rL4oeR0dX2yeyl2Tjx6tdaU9ZN21+viJGmn4zyjc81ccbHK/zxFFQeg3JU\n' +
  'xTOAv3qeIZC+QDzviraeGAEnzpTAHejXDWLfH0G1AfP0mZ4SjTTTZPLRfdVfqUnu\n' +
  '-----END RSA PRIVATE KEY-----\n'

const rsaPrivateKey =
  '-----BEGIN RSA PRIVATE KEY-----\n' +
  'MIIEpAIBAAKCAQEAqFvlHi5dBWLyDNsspY3cOHdK8UNhuyFJHQJ3qjVQqpc2W7LD\n' +
  'NKbsC3YUxShH9j8HyRYz3kbEPvEHT2dV2jqG0jvDRFldqri963FFk+0K8quOAezn\n' +
  'gbp51/x64w7DQjDp8SIYWkvYFpaAS7AU4AM5AzUsftbsxDo4QpNtadY9Xh1p6vWK\n' +
  '4k2dLwQ2Ara8AjuI6C+APkFp3wle/U21YO11FTKgBPGWLLJ/oG7+GrT/UJLgtiPJ\n' +
  'tNVPciBDDa6XxTeeeVp4op10MZVjDQK8szPAx0tWXhqnAe5EL7ZljQT/BF2+dxT8\n' +
  'ZQbp+tMXC0YVMwqjV6DJwt+cDQ7U7cDnknQ0iQIDAQABAoIBAD+lFbVWI5YwtH5F\n' +
  'sNgZC8JQ3oTcSyrZx3DvCNvQceE7brI1nvPdkmg2yF1MAABIDaJoAU2rBO8iYPgU\n' +
  'gXERJPx+2S+SdQVf93P1Cy+DsdrRHcr+ivoQy5Tp/m6tmwT/xsCAeiJQf6zyUifK\n' +
  'temFbl0XEe4VQ8Zel/wbDYawFdzotksHOppqnBgTjMGTio8ay3Vu1Ny7R1YiW/AB\n' +
  'ZjmZvnWB21CiCQBPzXSqI9YMftWQszmrhKCdjpIB4EoQxRavBY+6XLM23fB4l9Tq\n' +
  'Ekl/FOJ+X9v/7rTlS2w/b+LBGB8cPh7AUCPmuv4E27Pjc19dfQP2xNbxD7sK1l1R\n' +
  'UqjKxt0CgYEA30zBQMX/ZoHXA0gfY7VbzxbzBy6g8CAEve2YzrKTRhttQQ64u07P\n' +
  'd2BSByIGZbzRd/+B05Q5wGx8zdBtTJdjQCcWC2pSXFt9wOa6uB1kc/eaebu4DVEV\n' +
  'nKPGUgT+uajJh+bznmzDpQilZ9cmYnWa61Ws8jaD+qW8TDXIUCOlRjsCgYEAwQN4\n' +
  '+gs5DoFJIUZvVYuHkbkTHgA4Cg1y3F52FZ0QxFYnsPWb2/K4XqPKFsObu6pD/UG6\n' +
  'UDA6r1Z6sPRLC+J9lD3UVHIcZY6/cCng0ffjAu9L/MwMybB5bBsKecjiimvezf4+\n' +
  'nvOn1MYJlXIxSufViURNi3WF5VTnM3WgSTX7kAsCgYEA0KKVeeDFddBgxdcwROgh\n' +
  'hMeLgK1nf5Ra+d4yRQYCpqFfnkaUAaZsH7ymR7XZxlr6WCUp9zbqEskKfv578PEN\n' +
  'sdYTOc04cMSnJYIu+XG09slk0tK67+5PxBAdb2rtWSjES69U9jPnRJ5kdTZHzfzW\n' +
  'J4XgVlrrS1hpK8eghogXlxsCgYEAr379z7TGo0awfL3zWz/r+3bhSAUA7zr9Nhv5\n' +
  'mHtglHSV0FPx7FJMi1i31mzzO/Z7rVnHE0RXB7hFBIKLffnpHxH87u92nGzn6g9Z\n' +
  '6PBQjAmS+P97nSOFs+L+am9adGvSgVBsFdELx+5tJmJXKXmUciQVsfkgzr2dHvAT\n' +
  '1p1r57MCgYA6W5pXzpzT2plb6XDyOq5A4Mf0P52VEg6gIcRARhvujSrgkzsys78l\n' +
  'YCUTCLtRFKPH9Y6XFyO6NE70KI0GQSOm04YyTjBsWRfhziEeny+QMbWiQk3X+nU+\n' +
  '1qEwFwH2Z6Z4CsUf6h4rUbUopt0SmryGOhu5cseLVBTTH4XiC3dipA==\n' +
  '-----END RSA PRIVATE KEY-----\n'

const rsaPublicKey =
  '-----BEGIN PUBLIC KEY-----\n' +
  'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqFvlHi5dBWLyDNsspY3c\n' +
  'OHdK8UNhuyFJHQJ3qjVQqpc2W7LDNKbsC3YUxShH9j8HyRYz3kbEPvEHT2dV2jqG\n' +
  '0jvDRFldqri963FFk+0K8quOAezngbp51/x64w7DQjDp8SIYWkvYFpaAS7AU4AM5\n' +
  'AzUsftbsxDo4QpNtadY9Xh1p6vWK4k2dLwQ2Ara8AjuI6C+APkFp3wle/U21YO11\n' +
  'FTKgBPGWLLJ/oG7+GrT/UJLgtiPJtNVPciBDDa6XxTeeeVp4op10MZVjDQK8szPA\n' +
  'x0tWXhqnAe5EL7ZljQT/BF2+dxT8ZQbp+tMXC0YVMwqjV6DJwt+cDQ7U7cDnknQ0\n' +
  'iQIDAQAB\n' +
  '-----END PUBLIC KEY-----\n'

const pubKeys = {
  'test@test.com': {
    '1@RS256': rsaPublicKey,
    '1@RS384': rsaPublicKey,
    '1@RS512': rsaPublicKey
  }
}

const unixNow = Math.floor(Date.now() / 1000)

const jwtHeader = {
  typ: 'JWT',
  alg: 'RS256',
  kid: '1'
}

const jwtBody = {
  aud: 'https://host/oauth/token',
  iss: 'test@test.com',
  iat: unixNow,
  exp: unixNow + 600,
  scope: ['http://stuff', 'http://stuff2']
}

let suite = new Benchmark.Suite()

suite
  .add('Encrypted RSA key at RS256', () => {
    jwtUtils.encode(rsaPrivateKeyEncrypted, jwtHeader, jwtBody, 'Qwerty1234')
  })
  .add('Unencrypted RSA key at RS256', () => {
    jwtUtils.encode(rsaPrivateKey, jwtHeader, jwtBody)
  })
  // add listeners
  .on('cycle', function(event) {
    console.log(String(event.target))
  })
  .on('complete', function() {
    console.log('Fastest is ' + this.filter('fastest').map('name'))
  })
  // run async
  .run({ async: true })
