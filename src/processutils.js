const { spawn } = require('child_process')

class ProcessUtils {
  /**
   * @typedef {Object} ProcessResult
   * @property {number} code
   * @property {number} signal
   * @property {string} stdout
   * @property {string} stderr
   */

  /**
   * Run process returning a the handle and a with the result promise
   * @param {*} command
   * @param {*} args
   * @param {*} options
   * @returns {[ChildProcess, Promise<ProcessResult>]}
   */
  static runProcessAsync(command, args, options = {}) {
    let cmd = spawn(command, args, {
      env: options.env,
      detached: options.detached
    })

    let maxSize = options.maxSize || 10 * 1024 * 1024
    let stdOutMaxSize = options.stdOutMaxSize || maxSize
    let stdErrMaxSize = options.stdErrMaxSize || maxSize

    let promise = new Promise((resolve, reject) => {
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
          resolve({ code, signal })
        })
      })

      Promise.all([exitPromise, stdoutPromise, stderrPromise])
        .then(results => {
          resolve({
            code: results[0].code,
            signal: results[0].signal,
            stdout: results[1],
            stderr: results[2]
          })
        })
        .catch(reject)
    })
    return [cmd, promise]
  }
}

function readAllAsync(fd, maxSize) {
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

module.exports = ProcessUtils
