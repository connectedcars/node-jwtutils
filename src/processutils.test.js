const expect = require('unexpected')

const ProcessUtils = require('./processutils')

describe('ProcessUtils', () => {
  it('should timeout', () => {
    let [cmd, resultPromise] = ProcessUtils.runProcessAsync('sleep', ['10'], {
      timeout: 1
    })
    return expect(resultPromise, 'to be rejected with', new Error('Timeout'))
  })
  it('should generate stderr', () => {
    let [cmd, resultPromise] = ProcessUtils.runProcessAsync('sleep', ['--help'])
    return expect(resultPromise, 'to be fulfilled with', {
      stderr: 'usage: sleep seconds\n'
    })
  })
})
