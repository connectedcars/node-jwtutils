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
    console.log(`${command} ${args.join(' ')}`)
    let cmd = spawn(command, args, {
      env: options.env,
      detached: options.detached
    })

    let promise = new Promise((resolve, reject) => {
      if (options.timeout) {
        setTimeout(() => {
          reject(new Error('Timeout'))
          cmd.kill() // does not terminate the node process in the shell
        }, options.timeout)
      }

      // Read stdout
      let stdoutPromise = new Promise(resolve => {
        let stdData = []
        cmd.stdout.on('data', data => {
          stdData.push(data)
        })
        cmd.stdout.on('end', () => {
          resolve(Buffer.concat(stdData).toString('utf8'))
        })
      })

      let stderrPromise = new Promise(resolve => {
        // Read stderr
        let errorData = []
        cmd.stderr.on('data', data => {
          errorData.push(data)
        })
        cmd.stderr.on('end', () => {
          resolve(Buffer.concat(errorData).toString('utf8'))
        })
      })

      // Close stdin
      if (options.closeStdin) {
        cmd.stdin.end()
      }

      let exitPromise = new Promise(resolve => {
        cmd.on('exit', (code, signal) => {
          resolve({ code, signal })
        })
      })

      Promise.all([exitPromise, stdoutPromise, stderrPromise]).then(results => {
        resolve({
          code: results[0].code,
          signal: results[0].signal,
          stdout: results[1],
          stderr: results[2]
        })
      })
    })
    return [cmd, promise]
  }
}

module.exports = ProcessUtils
