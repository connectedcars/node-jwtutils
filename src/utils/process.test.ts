import fs from 'fs/promises'
import path from 'path'
import tmp from 'tmp'

import { runProcessAsync } from './process'

describe('process', () => {
  let tmpdir: tmp.DirResult
  let oldPath: string

  beforeAll(async () => {
    tmpdir = tmp.dirSync({ unsafeCleanup: true })
    process.env.PATH = `${tmpdir.name}${path.delimiter}${oldPath}`
    oldPath = process.env.PATH

    await fs.writeFile(
      `${tmpdir.name}/sleep`,
      `#!${process.argv[0]}\nsetTimeout(()=> {}, process.argv[1] * 1000)\nconsole.error('Done sleeping')`
    )

    await fs.chmod(`${tmpdir.name}/sleep`, '755')
  })

  afterAll(async () => {
    process.env['PATH'] = oldPath
    await fs.unlink(`${tmpdir.name}/sleep`)
    tmpdir.removeCallback()
  })

  it('should generate stderr', async () => {
    await expect(runProcessAsync(`${tmpdir.name}/sleep`, [])).resolves.toMatchObject({ stderr: 'Done sleeping\n' })
  })

  it('should overflow', async () => {
    await expect(
      runProcessAsync(`${tmpdir.name}/sleep`, [], {
        stdErrMaxSize: 5
      })
    ).rejects.toThrow(new Error('Data size larger than maxsize: 14 > 5'))
  })

  it('should timeout', async () => {
    await expect(
      runProcessAsync(`${tmpdir.name}/sleep`, ['10'], {
        timeout: 1
      })
    ).rejects.toThrow(new Error('Timeout'))
  })
})
