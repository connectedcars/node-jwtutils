import { spawn } from 'child_process'
import { Readable } from 'stream'

interface ProcessResult {
  code: number | null
  signal: string | null
  stdout: string
  stderr: string
}

interface ProcessOptions {
  detached?: boolean
  env?: NodeJS.ProcessEnv
  maxSize?: number
  stdOutMaxSize?: number
  stdErrMaxSize?: number
  timeout?: number
  closeStdin?: boolean
}

interface ExitResult {
  code: number | null
  signal: string | null
}

export async function runProcessAsync(
  command: string,
  args: string[],
  options: ProcessOptions = {}
): Promise<ProcessResult> {
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
        cmd.kill() // Does not terminate the node process in the shell
      }, options.timeout)
    }

    const stdoutPromise = readAllAsync(cmd.stdout, stdOutMaxSize)
    const stderrPromise = readAllAsync(cmd.stderr, stdErrMaxSize)

    // Close stdin
    if (options.closeStdin) {
      cmd.stdin.end()
    }

    const exitPromise = new Promise<ExitResult>(resolve => {
      cmd.on('exit', (code, signal) => {
        resolve({ code, signal })
      })
    })

    Promise.all([exitPromise, stdoutPromise, stderrPromise])
      .then(results => {
        resolve({
          code: results[0]['code'],
          signal: results[0]['signal'],
          stdout: results[1].toString('utf8'),
          stderr: results[2].toString('utf8')
        })
      })
      .catch(reject)
  })

  return promise.then((result: ProcessResult) => result)
}

async function readAllAsync(fd: Readable, maxSize: number): Promise<Buffer | string> {
  return new Promise((resolve, reject) => {
    const data: (Buffer | string)[] = []
    let dataLength = 0

    fd.on('data', (chunk: Buffer | string) => {
      dataLength += chunk.length

      if (dataLength > maxSize) {
        reject(new Error(`Data size larger than maxsize: ${dataLength} > ${maxSize}`))
        fd.destroy()
      }

      data.push(chunk)
    })

    fd.on('end', () => {
      if (typeof data[0] === 'string') {
        resolve(data.join(''))
      } else {
        resolve(Buffer.concat(data as Buffer[]))
      }
    })
  })
}
