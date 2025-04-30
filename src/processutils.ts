import { spawn } from 'child_process'
import { Readable } from 'stream'

interface ProcessResult {
  code: number
  signal: number
  stdout: string
  stderr: string
}

interface Options {
  detached?: boolean
  env?: NodeJS.ProcessEnv
  maxSize?: number
  stdOutMaxSize?: number
  stdErrMaxSize?: number
  timeout?: number
  closeStdin?: boolean
}

export async function runProcessAsync(command: string, args: string[], options: Options = {}): Promise<ProcessResult> {
  const cmd = spawn(command, args, {
    env: options.env,
    detached: options.detached
  })

  const maxSize = options.maxSize || 10 * 1024 * 1024
  const stdOutMaxSize = options.stdOutMaxSize || maxSize
  const stdErrMaxSize = options.stdErrMaxSize || maxSize

  const promise = new Promise<ProcessResult>((resolve, reject) => {
    if (options.timeout) {
      setTimeout(() => {
        reject(new Error('Timeout'))
        cmd.kill() // does not terminate the node process in the shell
      }, options.timeout)
    }

    const stdoutPromise = readAllAsync(cmd.stdout, stdOutMaxSize)
    const stderrPromise = readAllAsync(cmd.stderr, stdErrMaxSize)

    // Close stdin
    if (options.closeStdin) {
      cmd.stdin.end()
    }

    const exitPromise = new Promise(resolve => {
      cmd.on('exit', (code, signal) => {
        resolve({ code, signal })
      })
    })

    Promise.all([exitPromise, stdoutPromise, stderrPromise])
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      .then((results: any[]) => {
        resolve({
          code: results[0]['code'],
          signal: results[0]['signal'],
          stdout: results[1],
          stderr: results[2]
        })
      })
      .catch(reject)
  })

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return promise.then((result: any) => {
    return {
      code: result['code'],
      signal: result['signal'],
      stdout: result['stdout'],
      stderr: result['stderr']
    }
  })
}

async function readAllAsync(fd: Readable, maxSize: number): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const data: Buffer[] = []
    let dataLength = 0
    fd.on('data', (chunk: Buffer) => {
      dataLength += chunk.length
      if (dataLength > maxSize) {
        reject(new Error(`Data size larger than maxsize: ${dataLength} > ${maxSize}`))
        fd.destroy()
      }
      data.push(chunk)
    })
    fd.on('end', () => {
      resolve(Buffer.concat(data))
    })
  })
}
