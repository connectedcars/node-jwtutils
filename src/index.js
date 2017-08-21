const jwtEncode = require('./jwtencode')
const jwtDecode = require('./jwtdecode')

module.exports = {
  encode: jwtEncode,
  decode: jwtDecode
}
