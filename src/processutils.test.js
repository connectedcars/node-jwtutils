const expect = require('unexpected')

const ProcessUtils = require('./processutils')
const tmp = require('tmp')
const path = require('path')
const fs = require('fs')

describe('ProcessUtils', () => {
  let tmpdir
  let oldPath
  before(() => {
    tmpdir = tmp.dirSync()
    oldPath = process.env['PATH']
    process.env['PATH'] = `${tmpdir.name}${path.delimiter}${oldPath}`
    fs.writeFileSync(
      `${tmpdir.name}/sleep`,
      `#!${
        process.argv[0]
      }\nsetTimeout(()=> {}, process.argv[1] * 1000)\nconsole.error('Done sleeping')`
    )
    fs.chmodSync(`${tmpdir.name}/sleep`, '755')
  })
  after(() => {
    process.env['PATH'] = oldPath
    fs.unlinkSync(`${tmpdir.name}/sleep`)
    tmpdir.removeCallback()
  })

  it('should timeout', () => {
    let [cmd, resultPromise] = ProcessUtils.runProcessAsync('sleep', ['10'], {
      timeout: 1
    })
    return expect(resultPromise, 'to be rejected with', new Error('Timeout'))
  })
  it('should generate stderr', () => {
    let [cmd, resultPromise] = ProcessUtils.runProcessAsync('sleep', [])
    return expect(resultPromise, 'to be fulfilled with', {
      stderr: 'Done sleeping\n'
    })
  })
})
