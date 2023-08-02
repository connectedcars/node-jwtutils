import fs from 'fs'
import path from 'path'
import sinon from 'sinon'
import tmp from 'tmp'

import * as ProcessUtils from './processutils'

describe('ProcessUtils', () => {
  let clock: sinon.SinonFakeTimers

  let tmpdir: tmp.DirResult
  let oldPath: string
  beforeAll(async () => {
    clock = sinon.useFakeTimers()

    tmpdir = tmp.dirSync({ unsafeCleanup: true })
    process.env.PATH = `${tmpdir.name}${path.delimiter}${oldPath}`
    oldPath = process.env.PATH
    fs.writeFileSync(
      `${tmpdir.name}/sleep`,
      `#!${process.argv[0]}\nsetTimeout(()=> {}, process.argv[1] * 1000)\nconsole.error('Done sleeping')`
    )
    fs.chmodSync(`${tmpdir.name}/sleep`, '755')
  })
  afterEach(async () => {
    clock.restore()
  })
  afterAll(async () => {
    process.env['PATH'] = oldPath
    fs.unlinkSync(`${tmpdir.name}/sleep`)
    tmpdir.removeCallback()
    sinon.restore()
  })
  it('should generate stderr', async function () {
    clock.tick(3000)
    const resultPromise = await ProcessUtils.runProcessAsync(`${tmpdir.name}/sleep`, [])
    expect(resultPromise.stderr).toEqual(Buffer.from('Done sleeping\n'))
  })
  it('should overflow', async function () {
    clock.tick(3000)
    await expect(
      ProcessUtils.runProcessAsync(`${tmpdir.name}/sleep`, [], {
        stdErrMaxSize: 5
      })
    ).rejects.toThrow(new Error('Data size larger than maxsize: 14 > 5'))
  })
  it('should timeout', async function () {
    clock.tick(3000)
    await expect(
      ProcessUtils.runProcessAsync(`${tmpdir.name}/sleep`, ['10'], {
        timeout: 1
      })
    ).rejects.toThrow(new Error('Timeout'))
  })
})
