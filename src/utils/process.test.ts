import fs from 'fs'
import path from 'path'
import sinon from 'sinon'
import tmp from 'tmp'

import { runProcessAsync } from './process'

describe('process', () => {
  let clock: sinon.SinonFakeTimers
  let tmpdir: tmp.DirResult
  let oldPath: string

  beforeAll(() => {
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

  afterEach(() => {
    clock.restore()
  })

  afterAll(() => {
    process.env['PATH'] = oldPath
    fs.unlinkSync(`${tmpdir.name}/sleep`)
    tmpdir.removeCallback()
    sinon.restore()
  })

  it('should generate stderr', async () => {
    clock.tick(3000)
    const resultPromise = await runProcessAsync(`${tmpdir.name}/sleep`, [])
    expect(resultPromise.stderr).toEqual('Done sleeping\n')
  })

  it('should overflow', async () => {
    await clock.tickAsync(3000)

    await expect(
      runProcessAsync(`${tmpdir.name}/sleep`, [], {
        stdErrMaxSize: 5
      })
    ).rejects.toThrow(new Error('Data size larger than maxsize: 14 > 5'))
  })

  it('should timeout', async () => {
    await clock.tickAsync(3000)

    await expect(
      runProcessAsync(`${tmpdir.name}/sleep`, ['10'], {
        timeout: 1
      })
    ).rejects.toThrow(new Error('Timeout'))
  })
})
