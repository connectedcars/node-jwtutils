const rsaPublicKey =
  '-----BEGIN PUBLIC KEY-----\n' +
  'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDdlatRjRjogo3WojgGHFHYLugd\n' +
  'UWAY9iR3fy4arWNA1KoS8kVw33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQs\n' +
  'HUfQrSDv+MuSUMAe8jzKE4qW+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1/xAK5D\n' +
  'o2kQ+X5xK9cipRgEKwIDAQAB\n' +
  '-----END PUBLIC KEY-----'

const rsaPrivateKey =
  '-----BEGIN RSA PRIVATE KEY-----\n' +
  'MIICWwIBAAKBgQDdlatRjRjogo3WojgGHFHYLugdUWAY9iR3fy4arWNA1KoS8kVw\n' +
  '33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQsHUfQrSDv+MuSUMAe8jzKE4qW\n' +
  '+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1/xAK5Do2kQ+X5xK9cipRgEKwIDAQAB\n' +
  'AoGAD+onAtVye4ic7VR7V50DF9bOnwRwNXrARcDhq9LWNRrRGElESYYTQ6EbatXS\n' +
  '3MCyjjX2eMhu/aF5YhXBwkppwxg+EOmXeh+MzL7Zh284OuPbkglAaGhV9bb6/5Cp\n' +
  'uGb1esyPbYW+Ty2PC0GSZfIXkXs76jXAu9TOBvD0ybc2YlkCQQDywg2R/7t3Q2OE\n' +
  '2+yo382CLJdrlSLVROWKwb4tb2PjhY4XAwV8d1vy0RenxTB+K5Mu57uVSTHtrMK0\n' +
  'GAtFr833AkEA6avx20OHo61Yela/4k5kQDtjEf1N0LfI+BcWZtxsS3jDM3i1Hp0K\n' +
  'Su5rsCPb8acJo5RO26gGVrfAsDcIXKC+bQJAZZ2XIpsitLyPpuiMOvBbzPavd4gY\n' +
  '6Z8KWrfYzJoI/Q9FuBo6rKwl4BFoToD7WIUS+hpkagwWiz+6zLoX1dbOZwJACmH5\n' +
  'fSSjAkLRi54PKJ8TFUeOP15h9sQzydI8zJU+upvDEKZsZc/UhT/SySDOxQ4G/523\n' +
  'Y0sz/OZtSWcol/UMgQJALesy++GdvoIDLfJX5GBQpuFgFenRiRDabxrE9MNUZ2aP\n' +
  'FaFp+DyAe+b4nDwuJaW2LURbr8AEZga7oQj0uYxcYw==\n' +
  '-----END RSA PRIVATE KEY-----'

const rsaOtherPublicKey =
  '-----BEGIN PUBLIC KEY-----\n' +
  'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDf6PME6PIAF47/UzLDixmtlLvn\n' +
  'RkSGzixmdGJUurUZyz3B2ok5DIYYtdN1LWXmt0BRfA5B9SQAsZ4h9tdAs5zjVUe1\n' +
  's9oLHK0++UEM7vowvhqvMmxeVmcABtsx0IoXTryLLKcrdJQfmmeAItZAyYbz6Tzp\n' +
  'O6x06JSme6Xy0lOQawIDAQAB\n' +
  '-----END PUBLIC KEY-----'

const ecPrivateKey =
  '-----BEGIN EC PRIVATE KEY-----\n' +
  'MHQCAQEEIEbBJ5shjRhQjmWZQfBu8t069BolPpmZjg+c2mSqr8BkoAcGBSuBBAAK\n' +
  'oUQDQgAEgYq9+AtlLZMXL2g61gwOG3vPQPeaWQD+3JcRUdcwdZm4duMXQZrwVBSr\n' +
  '5Kunr1NnK+0VCrcoUh09GFr8UTAq3g==\n' +
  '-----END EC PRIVATE KEY-----'

const ecPublicKey =
  '-----BEGIN PUBLIC KEY-----\n' +
  'MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEgYq9+AtlLZMXL2g61gwOG3vPQPeaWQD+\n' +
  '3JcRUdcwdZm4duMXQZrwVBSr5Kunr1NnK+0VCrcoUh09GFr8UTAq3g==\n' +
  '-----END PUBLIC KEY-----\n'

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

const rsaPublicKeyEncrypted =
  '-----BEGIN PUBLIC KEY-----\n' +
  'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqFvlHi5dBWLyDNsspY3c\n' +
  'OHdK8UNhuyFJHQJ3qjVQqpc2W7LDNKbsC3YUxShH9j8HyRYz3kbEPvEHT2dV2jqG\n' +
  '0jvDRFldqri963FFk+0K8quOAezngbp51/x64w7DQjDp8SIYWkvYFpaAS7AU4AM5\n' +
  'AzUsftbsxDo4QpNtadY9Xh1p6vWK4k2dLwQ2Ara8AjuI6C+APkFp3wle/U21YO11\n' +
  'FTKgBPGWLLJ/oG7+GrT/UJLgtiPJtNVPciBDDa6XxTeeeVp4op10MZVjDQK8szPA\n' +
  'x0tWXhqnAe5EL7ZljQT/BF2+dxT8ZQbp+tMXC0YVMwqjV6DJwt+cDQ7U7cDnknQ0\n' +
  'iQIDAQAB\n' +
  '-----END PUBLIC KEY-----\n'

module.exports = {
  rsaPublicKey,
  rsaPrivateKey,
  rsaOtherPublicKey,
  ecPrivateKey,
  ecPublicKey,
  rsaPrivateKeyEncrypted,
  rsaPublicKeyEncrypted
}
