process.env.TZ = 'UTC'
process.env.USE_INTEGRATION_TEST_CHECKOUTS = true

module.exports = {
  ...require('./node_modules/@connectedcars/setup/jest.config.js')
}
