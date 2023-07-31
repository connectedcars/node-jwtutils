import { spawn } from 'child_process'

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
    let cmd = spawn(command, args, {
      env: options.env,
      detached: options.detached
    })

    let maxSize = options.maxSize || 10 * 1024 * 1024
    let stdOutMaxSize = options.stdOutMaxSize || maxSize
    let stdErrMaxSize = options.stdErrMaxSize || maxSize

    const promise = new Promise((resolve, reject) => {
      if (options.timeout) {
        setTimeout(() => {
          reject(new Error('Timeout'))
          cmd.kill() // does not terminate the node process in the shell
        }, options.timeout)
      }

      let stdoutPromise = readAllAsync(cmd.stdout, stdOutMaxSize)
      let stderrPromise = readAllAsync(cmd.stderr, stdErrMaxSize)

      // Close stdin
      if (options.closeStdin) {
        cmd.stdin.end()
      }

      let exitPromise = new Promise(resolve => {
        cmd.on('exit', (code, signal) => {
          resolve({ code, signal });
        })
      })

      
      Promise.all([exitPromise, stdoutPromise, stderrPromise])
        .then(results => {
          resolve({
            code: results[0]['code'],
            signal: results[0]['signal'],
            stdout: results[1],
            stderr: results[2]
          })
        })
        .catch(reject)
    })

    return promise.then(result => {
      return {
        code: result['code'],
        signal: result['signal'],
        stdout: result['stdout'],
        stderr: result['stderr']
      }
    })
  }


  async function readAllAsync(fd: any, maxSize: number): Promise<Buffer> {
    return new Promise((resolve, reject) => {
      let data = []
      let dataLength = 0
      fd.on('data', chunk => {
        dataLength += chunk.length
        if (dataLength > maxSize) {
          fd.destroy()
          reject(
            new Error(`Data size larger than maxsize: ${dataLength} > ${maxSize}`)
          )
        }
        data.push(chunk)
      })
      fd.on('end', () => {
        resolve(Buffer.concat(data))
      })
    })
  }
