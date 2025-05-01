import { JwkBody } from './pubkeys-helper'

export const rsaPublicKey =
  '-----BEGIN PUBLIC KEY-----\n' +
  'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDdlatRjRjogo3WojgGHFHYLugd\n' +
  'UWAY9iR3fy4arWNA1KoS8kVw33cJibXr8bvwUAUparCwlvdbH6dvEOfou0/gCFQs\n' +
  'HUfQrSDv+MuSUMAe8jzKE4qW+jK+xQU9a03GUnKHkkle+Q0pX/g6jXZ7r1/xAK5D\n' +
  'o2kQ+X5xK9cipRgEKwIDAQAB\n' +
  '-----END PUBLIC KEY-----'

export const rsaPublicKey4096 =
  '-----BEGIN PUBLIC KEY-----\n' +
  'MIICITANBgkqhkiG9w0BAQEFAAOCAg4AMIICCQKCAgBlY+Tg7Jvp8ispsOkCRbYn\n' +
  'uXgp+EpxcRrPRe35Lxxf3qdU3Y2+NWafofhXmSISoYcQk4kecNqb0V9u5pJv/sN9\n' +
  'H61wOaRf4sib2xD20x6EQat7B0My+Vj9CYXXx7ic48jh3UxjHx5RkyPG7EAJ4wOc\n' +
  '+Z/vmhJ0d+dTUEJ7pDX9KDqofzbCRAMkX+U3Dn6sipTuWjOf1MpkaV1Chj+FnIc6\n' +
  'hq/3Ur6GsNkxGdLKEv6SHzTIFnYkHYClKpBgcwEM6rkSuu0TQeXPlZmbiP7tiZSD\n' +
  'prsccux1rybQ2XAkrBO2xikRLZnetDqFv3rMu/1r9iVF5CX64g3bMj1qAqU1kbIK\n' +
  'nLJmDGOZuvdGsbrMeoJiAL7+EBkcNlpxaTaGdU3XAO/na93/DTccE6jzjgRqQwQj\n' +
  'OdKzzkDvbq9vfWbSHw+MSn+TxcPNd4ngOwXiFAQai36pStdX9Gy7JSW7leiF92I8\n' +
  'OGk9P66rmMg/wFqEDI+BMzgs9CrOt07mzxU4DfPgHIv1MTHUdxl0h9Yxa/q3D9FR\n' +
  'PWkYvTkOOLEmZywDF2vms0tn0fEv/pgPyA/oMc3N/5hz/JeJJ9Yn/+hWnWasDO9w\n' +
  'us97LhyX+DqEoSOablW55bzcVln3w4y/h2LFgm8wsvtgbPSFLG5vBYulEsNu3kAA\n' +
  'Mga75gS0l2bSUAW7dewK0QIDAQAB\n' +
  '-----END PUBLIC KEY-----'

export const rsaPublicKey4096Jwk = {
  kty: 'RSA',
  n: 'ZWPk4Oyb6fIrKbDpAkW2J7l4KfhKcXEaz0Xt-S8cX96nVN2NvjVmn6H4V5kiEqGHEJOJHnDam9FfbuaSb_7DfR-tcDmkX-LIm9sQ9tMehEGrewdDMvlY_QmF18e4nOPI4d1MYx8eUZMjxuxACeMDnPmf75oSdHfnU1BCe6Q1_Sg6qH82wkQDJF_lNw5-rIqU7lozn9TKZGldQoY_hZyHOoav91K-hrDZMRnSyhL-kh80yBZ2JB2ApSqQYHMBDOq5ErrtE0Hlz5WZm4j-7YmUg6a7HHLsda8m0NlwJKwTtsYpES2Z3rQ6hb96zLv9a_YlReQl-uIN2zI9agKlNZGyCpyyZgxjmbr3RrG6zHqCYgC-_hAZHDZacWk2hnVN1wDv52vd_w03HBOo844EakMEIznSs85A726vb31m0h8PjEp_k8XDzXeJ4DsF4hQEGot-qUrXV_RsuyUlu5XohfdiPDhpPT-uq5jIP8BahAyPgTM4LPQqzrdO5s8VOA3z4ByL9TEx1HcZdIfWMWv6tw_RUT1pGL05DjixJmcsAxdr5rNLZ9HxL_6YD8gP6DHNzf-Yc_yXiSfWJ__oVp1mrAzvcLrPey4cl_g6hKEjmm5VueW83FZZ98OMv4dixYJvMLL7YGz0hSxubwWLpRLDbt5AADIGu-YEtJdm0lAFu3XsCtE',
  e: 'AQAB'
} as JwkBody

export const rsaPublicKeyJwk = {
  kty: 'RSA',
  n: '3ZWrUY0Y6IKN1qI4BhxR2C7oHVFgGPYkd38uGq1jQNSqEvJFcN93CYm16_G78FAFKWqwsJb3Wx-nbxDn6LtP4AhULB1H0K0g7_jLklDAHvI8yhOKlvoyvsUFPWtNxlJyh5JJXvkNKV_4Oo12e69f8QCuQ6NpEPl-cSvXIqUYBCs',
  e: 'AQAB'
} as JwkBody

export const rsaPrivateKey =
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

export const rsaOtherPublicKey =
  '-----BEGIN PUBLIC KEY-----\n' +
  'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDf6PME6PIAF47/UzLDixmtlLvn\n' +
  'RkSGzixmdGJUurUZyz3B2ok5DIYYtdN1LWXmt0BRfA5B9SQAsZ4h9tdAs5zjVUe1\n' +
  's9oLHK0++UEM7vowvhqvMmxeVmcABtsx0IoXTryLLKcrdJQfmmeAItZAyYbz6Tzp\n' +
  'O6x06JSme6Xy0lOQawIDAQAB\n' +
  '-----END PUBLIC KEY-----'

export const ecPrivateKey =
  '-----BEGIN EC PRIVATE KEY-----\n' +
  'MHQCAQEEIEbBJ5shjRhQjmWZQfBu8t069BolPpmZjg+c2mSqr8BkoAcGBSuBBAAK\n' +
  'oUQDQgAEgYq9+AtlLZMXL2g61gwOG3vPQPeaWQD+3JcRUdcwdZm4duMXQZrwVBSr\n' +
  '5Kunr1NnK+0VCrcoUh09GFr8UTAq3g==\n' +
  '-----END EC PRIVATE KEY-----'

export const ecPublicKey =
  '-----BEGIN PUBLIC KEY-----\n' +
  'MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEgYq9+AtlLZMXL2g61gwOG3vPQPeaWQD+\n' +
  '3JcRUdcwdZm4duMXQZrwVBSr5Kunr1NnK+0VCrcoUh09GFr8UTAq3g==\n' +
  '-----END PUBLIC KEY-----'

export const ecPublicKeyJwk = {
  kty: 'EC',
  crv: 'K-256',
  x: 'gYq9-AtlLZMXL2g61gwOG3vPQPeaWQD-3JcRUdcwdZk',
  y: 'uHbjF0Ga8FQUq-Srp69TZyvtFQq3KFIdPRha_FEwKt4'
} as JwkBody

export const rsaPrivateKeyEncrypted =
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
  '-----END RSA PRIVATE KEY-----'

export const rsaPublicKeyEncrypted =
  '-----BEGIN PUBLIC KEY-----\n' +
  'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqFvlHi5dBWLyDNsspY3c\n' +
  'OHdK8UNhuyFJHQJ3qjVQqpc2W7LDNKbsC3YUxShH9j8HyRYz3kbEPvEHT2dV2jqG\n' +
  '0jvDRFldqri963FFk+0K8quOAezngbp51/x64w7DQjDp8SIYWkvYFpaAS7AU4AM5\n' +
  'AzUsftbsxDo4QpNtadY9Xh1p6vWK4k2dLwQ2Ara8AjuI6C+APkFp3wle/U21YO11\n' +
  'FTKgBPGWLLJ/oG7+GrT/UJLgtiPJtNVPciBDDa6XxTeeeVp4op10MZVjDQK8szPA\n' +
  'x0tWXhqnAe5EL7ZljQT/BF2+dxT8ZQbp+tMXC0YVMwqjV6DJwt+cDQ7U7cDnknQ0\n' +
  'iQIDAQAB\n' +
  '-----END PUBLIC KEY-----'

export const rsaPublicKeyEncryptedJwk = {
  kty: 'RSA',
  n: 'qFvlHi5dBWLyDNsspY3cOHdK8UNhuyFJHQJ3qjVQqpc2W7LDNKbsC3YUxShH9j8HyRYz3kbEPvEHT2dV2jqG0jvDRFldqri963FFk-0K8quOAezngbp51_x64w7DQjDp8SIYWkvYFpaAS7AU4AM5AzUsftbsxDo4QpNtadY9Xh1p6vWK4k2dLwQ2Ara8AjuI6C-APkFp3wle_U21YO11FTKgBPGWLLJ_oG7-GrT_UJLgtiPJtNVPciBDDa6XxTeeeVp4op10MZVjDQK8szPAx0tWXhqnAe5EL7ZljQT_BF2-dxT8ZQbp-tMXC0YVMwqjV6DJwt-cDQ7U7cDnknQ0iQ',
  e: 'AQAB'
} as JwkBody

export const localhostCertificate =
  '-----BEGIN CERTIFICATE-----\n' +
  'MIIC/DCCAeQCCQCaq+pPRSkopTANBgkqhkiG9w0BAQsFADBAMQswCQYDVQQGEwJE\n' +
  'SzESMBAGA1UEAwwJbG9jYWxob3N0MR0wGwYJKoZIhvcNAQkBFg50ZXN0QGxvY2Fs\n' +
  'aG9zdDAeFw0xODAxMjEyMDU3MzJaFw0yODAxMTkyMDU3MzJaMEAxCzAJBgNVBAYT\n' +
  'AkRLMRIwEAYDVQQDDAlsb2NhbGhvc3QxHTAbBgkqhkiG9w0BCQEWDnRlc3RAbG9j\n' +
  'YWxob3N0MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEApdWZLLnAr0jR\n' +
  't7KGQKj51/GbBDjIN16I/O4ZlJHxrzOnkoxOrSm+mkh+hTLxEKwsCzPclP/MTg4S\n' +
  'pFsyyhiF8sBfopB/KMmQ1OoT65cG0mZTCv9cv49STvQ2bkEfCdvUWQNp9YX5HBNq\n' +
  'RUlgAQM/AW9uetjhX+aJK0Ot6C5Nnp2rOX7FlW5ruZ64cRjr4pAxVjWI1B0h/Sa1\n' +
  'RPXaOUrVoEaVrZ7I6HO6HVeQVeAgSe0y9b9gtrqx9YxQEdo2lQR8z90ttC7uATDO\n' +
  'WgH5pJ7GWt7utfJksZFcZ/EdTRp10kNqlALZnrEtSNRD47mRloybZ39aBfzIKdUl\n' +
  'i4CeDgnhoQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQBsEY0g2JIBmsW6EYVyTqN9\n' +
  'IlBgG0eT//I17/wgvZ6X+8iHK/vk9uIn1qqu7MfBVw9ZHwpA0JA86YCyeEBsh8OD\n' +
  'UxlQA3+ovGpjv39iBfof+MbzQ3QjOvMPuykqbilm/dA9f0tXT6nKOQ7fS6uS6Q5v\n' +
  'EHtkHk+8t1IMAW2NpOfMphGMeAofko5jNTzqyGVMHK1ts6bmkq2iCv+BFJZip5EU\n' +
  '8SIxuHF5v/WAPaS1cl8DGsUxYDIWuIXhZVkmHYDux6TMyV9HtAEmvhm9Hh86ayi0\n' +
  'ZP60ZUsPY4r3yAn0b2PvY1wmYGOgeWnBdHx593/gsUthBYoMRVPv4OTqClJTqMGk\n' +
  '-----END CERTIFICATE-----'

export const localhostPrivateKey =
  '-----BEGIN PRIVATE KEY-----\n' +
  'MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCl1ZksucCvSNG3\n' +
  'soZAqPnX8ZsEOMg3Xoj87hmUkfGvM6eSjE6tKb6aSH6FMvEQrCwLM9yU/8xODhKk\n' +
  'WzLKGIXywF+ikH8oyZDU6hPrlwbSZlMK/1y/j1JO9DZuQR8J29RZA2n1hfkcE2pF\n' +
  'SWABAz8Bb2562OFf5okrQ63oLk2enas5fsWVbmu5nrhxGOvikDFWNYjUHSH9JrVE\n' +
  '9do5StWgRpWtnsjoc7odV5BV4CBJ7TL1v2C2urH1jFAR2jaVBHzP3S20Lu4BMM5a\n' +
  'AfmknsZa3u618mSxkVxn8R1NGnXSQ2qUAtmesS1I1EPjuZGWjJtnf1oF/Mgp1SWL\n' +
  'gJ4OCeGhAgMBAAECggEAKTXBUMoARg7Ufs/QaPUU0ULrAMuThZ7qb+BDXxY9dwph\n' +
  'FBvl2UZMZU6qkjMskLYYY9hJcoV2odcBbvJy1qHtd3uyyFUcJGiioyZgOOVY/qQK\n' +
  '8uqug7P8Aj7R3+gy7GJCjLQ6epcGZqG0gO9Q+i9yUsr8K28F4q0JXUT+THplM4sY\n' +
  'f8BRyuU5WiNESY2Z/wxdO+n2nbl1OAZ6vZZsxpSsPHdO71HT/evaOKXq6/pw8+gk\n' +
  'zSmSNXFUhSKJnlcz20w7vDCsBJug0GtW/Sbucyws757tX6oQ5tqpskn3lxzuYfdv\n' +
  'baZfd0z+GYwzEeb8hXAGkGjnPLu4mvsW/rfmX5bFoQKBgQDO+Goq8VTd/bVnNJl7\n' +
  'eftA+2aOh0zq20HNu5EQuCNuQPd7G2WycWNq+cI2PGXcCa1A6Uy2e3ppUCane5ri\n' +
  '6yUZwZNb2Dtjhno+RQ2OHWiNsVRM7niHpsknskRREJrnlICbWkbwYUCSAa3Q758j\n' +
  '4T1FezCJ+020saG2nIqzwH4gvQKBgQDNHoRnqS1C6+hWCJBcHuqyiwwNs8WTELvV\n' +
  'laLfHjogxqcr0h/ioLCsH/dBvJaT4MlhqiKiMuVVh0NI8EXk7k/TGCdMKhyjuS2Y\n' +
  'uDa6p/XdrwubSy3GRDnonVjkPO4hk8dAcsQJN7X/7x50ParZKCT9EoNyDDWUElCj\n' +
  'wJtbRJFstQKBgQDBmV7+EkZXbLXd9zbGaIDc9Qymr+sEGNpBznzQjd4eiMi2MBd9\n' +
  'xlC/xSakwvRo0ehtOo3WeEQ19JJjwdxM/LX0lLz5gZdz7lu0mbUnRV0ChWicmcjG\n' +
  '4v1wk3ER/x1XF/MA3n5S5jWXHdjwAuTylANTVfs+ZoL2Td49ycp4f8u7ZQKBgAsO\n' +
  'wxqHfz4lU5AXxBiDPinD3zF56IPGGiood/BJQ97ydp6hJEDmYr/UtVKg5QkxzAls\n' +
  'z5Mo5T4YHaN3+Hyf8EO0AKJVftfAqtmZzLGBTnrV7e1AP0Z59Rk6Kkmbk0bSHaK2\n' +
  'zSSmETSr4ltn26b7SAswjU9/ov/JgPli770a1DAlAoGAdWqRDR9bgy48FpiqV4CG\n' +
  'YGxOcQftDc/sgWncAqVPdm+LrV0hBKGLB+MZeLaPqmYXy16v7q5YWWwGwAabbFRg\n' +
  'tf3PO/1A+cD/vOd4Kcg98uIIgmMdVxCZaBjzsRb1wp9AKTWIMCvBEii9XmXGkXi2\n' +
  'eG8Nor88jMLTDJoCfYWy+So=\n' +
  '-----END PRIVATE KEY-----'
