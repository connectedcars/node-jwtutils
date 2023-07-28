import { rsaPrivateKey, rsaPublicKey } from './testresources'

// import { JwtServiceAuth, } from './index'
import { JwtServiceAuth } from './jwtserviceauth'

import fs from 'fs'
import path from 'path'
import tmp from 'tmp'

import { JwtServiceAuthTestServer } from './jwtserviceauth-test-server'

import r2 from 'r2'
import curl from 'url'
import { defaultHttpRequestHandler } from './defaulthttprequesthandler'
import { JwtServiceAuthError } from './jwtserviceautherror'

//todo: grace rewrite this test


const googleKeyFileData = {
  type: 'service_account',
  project_id: 'test-project',
  private_key_id: '76d81ae69ce620a517b140fc73dbae61e88b34bc',
  private_key: rsaPrivateKey,
  client_email: 'buildstatus@nversion-168820.iam.gserviceaccount.com',
  client_id: '123456789123456789123',
  auth_uri: 'https://accounts.google.com/o/oauth2/auth',
  token_uri: 'https://accounts.google.com/o/oauth2/token',
  auth_provider_x509_cert_url: 'https://www.googleapis.com/oauth2/v1/certs',
  client_x509_cert_url:
    'https://www.googleapis.com/robot/v1/metadata/x509/servicename%40test-project.iam.gserviceaccount.com'
}



describe('JwtServiceAuth', () => {
  // Setup httpRequestHandler
  const server = new JwtServiceAuthTestServer()

  let httpRequestHandlerR2  = null
  let baseUrl = null
  beforeAll(async () => {
    await server.start()
    baseUrl = `http://localhost:${server.listenPort}`
    httpRequestHandlerR2 = defaultHttpRequestHandler
  })

  afterEach(async () => {
    server.reset()
  })

  afterAll(async () => {
    await server.stop()
  })

  describe('getGoogleAccessToken', () => {
    it('should succeed with ok token', async () => {
      const jwtServiceAuth = new JwtServiceAuth(httpRequestHandlerR2,  {endpoint: `${baseUrl}/oauth2/v4/token`})
      const accessTokenPromise = await jwtServiceAuth.getGoogleAccessToken(
        JSON.stringify(googleKeyFileData)
      )
      return expect(
        accessTokenPromise).toEqual(
        {
          accessToken: 'ok',
          expiresAt: expect.any(Number),
          expiresIn: expect.any(Number)
        }
      )
    })

    it('should succeed with ok token with other scope', async () => {
      const jwtServiceAuth = new JwtServiceAuth(httpRequestHandlerR2, {endpoint: `${baseUrl}/oauth2/v4/token`})
      const accessTokenPromise = await jwtServiceAuth.getGoogleAccessToken(
        JSON.stringify(googleKeyFileData),
        ['https://www.googleapis.com/auth/admin.datatransfer']
      )
      return expect(
        accessTokenPromise).toEqual(
        {
          accessToken: 'ok',
          expiresAt: expect.any(Number),
          expiresIn: expect.any(Number)
        }
      )
    })

    it('should succeed with ok token old expires interface', async () => {
      const jwtServiceAuth = new JwtServiceAuth(httpRequestHandlerR2, {endpoint: `${baseUrl}/oauth2/v4/token`})
      const accessTokenPromise = await jwtServiceAuth.getGoogleAccessToken(
        JSON.stringify(googleKeyFileData),
        3600,
        null
      )
      return expect(
        accessTokenPromise).toEqual(
        {
          accessToken: 'ok',
          expiresAt: expect.any(Number),
          expiresIn: expect.any(Number)
        }
      )
    })


    it('should fail', async () => {
      const jwtServiceAuth = new JwtServiceAuth(httpRequestHandlerR2,  {endpoint: `${baseUrl}`})
      await expect(jwtServiceAuth.getGoogleAccessToken(
        JSON.stringify(googleKeyFileData)
      )).rejects.toThrow(new JwtServiceAuthError('Request failed with status code 400'))
    })

    it('should fail with bad input', async () => {
      const jwtServiceAuth = new JwtServiceAuth(httpRequestHandlerR2,  {endpoint: `${baseUrl}/oauth2/v4/token`})
      await expect(jwtServiceAuth.getGoogleAccessToken(
        '{}'
      )).rejects.toThrow(new JwtServiceAuthError('Only supports service account keyFiles'))
    })

    it('should succeed with ok token and impersonate', async () => {
      const jwtServiceAuth = new JwtServiceAuth(httpRequestHandlerR2, {endpoint: `${baseUrl}/oauth2/v4/token`})
      const accessTokenPromise = await jwtServiceAuth.getGoogleAccessToken(
        JSON.stringify(googleKeyFileData),
        null,
        { impersonate: 'test' }
      )
      return expect(
        accessTokenPromise).toEqual(
        {
          accessToken: 'ok',
          expiresAt: expect.any(Number),
          expiresIn: expect.any(Number)
        }
      )
    })
  })

  // describe('getGoogleAccessTokenFromGCloudHelper', () => {
  //   const tmpdir
  //   const oldPath
  //   before(() => {
  //     tmpdir = tmp.dirSync()
  //     oldPath = process.env['PATH']
  //     process.env['PATH'] = `${tmpdir.name}${path.delimiter}${oldPath}`
  //     const configString = JSON.stringify(
  //       {
  //         configuration: {
  //           active_configuration: 'buildstatus',
  //           properties: {
  //             compute: {
  //               region: 'europe-west1',
  //               zone: 'europe-west1-a'
  //             },
  //             core: {
  //               account: 'troels@connectedcars.dk',
  //               disable_usage_reporting: 'True',
  //               project: 'buildstatus'
  //             }
  //           }
  //         },
  //         credential: {
  //           access_token: 'ok',
  //           token_expiry: new Date(
  //             new Date().getTime() + 3600 * 1000
  //           ).toISOString()
  //         },
  //         sentinels: {
  //           config_sentinel: '/user/buildstatus/.config/gcloud/config_sentinel'
  //         }
  //       },
  //       null,
  //       2
  //     )
  //     fs.writeFileSync(
  //       `${tmpdir.name}/gcloud`,
  //       `#!${process.argv[0]}\nconsole.log(\`${configString}\`)`
  //     )
  //     fs.chmodSync(`${tmpdir.name}/gcloud`, '755')
  //   })
  //   after(() => {
  //     process.env['PATH'] = oldPath
  //     fs.unlinkSync(`${tmpdir.name}/gcloud`)
  //     tmpdir.removeCallback()
  //   })

  //   it('should succeed with ok token', function() {
  //     this.timeout(10000)
  //     this.slow(5000)
  //     const jwtServiceAuth = new JwtServiceAuth()
  //     const accessTokenPromise = jwtServiceAuth.getGoogleAccessTokenFromGCloudHelper()
  //     return expect(
  //       accessTokenPromise,
  //       'to be fulfilled with value satisfying',
  //       {
  //         accessToken: 'ok',
  //         expiresIn: expect
  //           .it('to be a number')
  //           .and('to be greater than', 1000),
  //         expiresAt: expect
  //           .it('to be a number')
  //           .and('to be greater than', 1500000000)
  //       }
  //     )
  //   })
  //   it('static should succeed with ok token ', function() {
  //     this.timeout(10000)
  //     this.slow(5000)
  //     const accessTokenPromise = JwtServiceAuth.getGoogleAccessTokenFromGCloudHelper()
  //     return expect(
  //       accessTokenPromise,
  //       'to be fulfilled with value satisfying',
  //       {
  //         accessToken: 'ok',
  //         expiresIn: expect
  //           .it('to be a number')
  //           .and('to be greater than', 1000),
  //         expiresAt: expect
  //           .it('to be a number')
  //           .and('to be greater than', 1500000000)
  //       }
  //     )
  //   })
  // })
})
