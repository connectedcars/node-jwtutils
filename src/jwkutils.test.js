// @ts-check
'use strict'

const expect = require('unexpected')
const jwkUtils = require('./jwkutils')

const {
  rsaPublicKey,
  rsaPublicKeyJwk,
  rsaPublicKeyEncrypted,
  rsaPublicKeyEncryptedJwk,
  rsaPublicKey4096,
  rsaPublicKey4096Jwk,
  ecPublicKey,
  ecPublicKeyJwk
} = require('./testresources')

describe('jwkutils', () => {
  it('rsaPublicJwkToPem 1024bit', () => {
    let generatedPem = jwkUtils.rsaPublicJwkToPem(rsaPublicKeyJwk)
    expect(generatedPem, 'to equal', rsaPublicKey)
  })
  it('rsaPublicJwkToPem 2048bit', () => {
    let generatedPem = jwkUtils.rsaPublicJwkToPem(rsaPublicKeyEncryptedJwk)
    expect(generatedPem, 'to equal', rsaPublicKeyEncrypted)
  })
  it('rsaPublicJwkToPem 4096bit', () => {
    let generatedPem = jwkUtils.rsaPublicJwkToPem(rsaPublicKey4096Jwk)
    expect(generatedPem, 'to equal', rsaPublicKey4096)
  })
  it('ecPublicJwkToPem K-256', () => {
    let generatedPem = jwkUtils.ecPublicKeyJwkToPem(ecPublicKeyJwk)
    expect(generatedPem, 'to equal', ecPublicKey)
  })
  it('ecPublicJwkToPem P-256', () => {
    let jwk = {
      crv: 'P-256',
      kty: 'EC',
      x: 'gh9MmXjtmcHFesofqWZ6iuxSdAYgoPVvfJqpv1818lo',
      y: '3BDZHsNvKUb5VbyGPqcAFf4FGuPhJ2Xy215oWDw_1jc'
    }
    let expected =
      '-----BEGIN PUBLIC KEY-----\n' +
      'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgh9MmXjtmcHFesofqWZ6iuxSdAYg\n' +
      'oPVvfJqpv1818lrcENkew28pRvlVvIY+pwAV/gUa4+EnZfLbXmhYPD/WNw==\n' +
      '-----END PUBLIC KEY-----'
    let generatedPem = jwkUtils.ecPublicKeyJwkToPem(jwk)
    expect(generatedPem, 'to equal', expected)
  })
  it('ecPublicJwkToPem P-384', () => {
    var jwk = {
      crv: 'P-384',
      kty: 'EC',
      x: 'QIRvRhN2MpnTQ4teO4Y_RYFaK2Qlvc2lbhC0vALwrFOy33kUihkNUvHiTaUsp2W3',
      y: 'vSA1sCKKzT4UOavStUL2WpwcCflEyDshzy3dc1IZtACUngU2xMDDMsi0gDL9jLiU'
    }
    var expected =
      '-----BEGIN PUBLIC KEY-----\n' +
      'MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEQIRvRhN2MpnTQ4teO4Y/RYFaK2Qlvc2l\n' +
      'bhC0vALwrFOy33kUihkNUvHiTaUsp2W3vSA1sCKKzT4UOavStUL2WpwcCflEyDsh\n' +
      'zy3dc1IZtACUngU2xMDDMsi0gDL9jLiU\n' +
      '-----END PUBLIC KEY-----'
    let generatedPem = jwkUtils.ecPublicKeyJwkToPem(jwk)
    expect(generatedPem, 'to equal', expected)
  })
  it('ecPublicJwkToPem P-521', () => {
    var jwk = {
      crv: 'P-521',
      kty: 'EC',
      x:
        'AFqLf9vO672gS-Lv_BabqzKoedNLQgZkCemRZuzYu4KJjHgPBZ5fs3S05MoRXl4e7lR026XDDNPXawySVDXta9KF',
      y:
        'APbUNzQ7IP_Mi0XwLN_RWZcIyHI43MJIAEn7O-KS0r8lvxjnVXeoopWAdqfTX_fCHXpYN1Ux1soOWujXb1uCEb7G'
    }
    var expected =
      '-----BEGIN PUBLIC KEY-----\n' +
      'MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAWot/287rvaBL4u/8FpurMqh500tC\n' +
      'BmQJ6ZFm7Ni7gomMeA8Fnl+zdLTkyhFeXh7uVHTbpcMM09drDJJUNe1r0oUA9tQ3\n' +
      'NDsg/8yLRfAs39FZlwjIcjjcwkgASfs74pLSvyW/GOdVd6iilYB2p9Nf98Idelg3\n' +
      'VTHWyg5a6NdvW4IRvsY=\n' +
      '-----END PUBLIC KEY-----'
    let generatedPem = jwkUtils.ecPublicKeyJwkToPem(jwk)
    expect(generatedPem, 'to equal', expected)
  })
  it('jwkToPem K-256, RSA', () => {
    let generatedEcPem = jwkUtils.jwkToPem(ecPublicKeyJwk)
    expect(generatedEcPem, 'to equal', ecPublicKey)
    let generatedRsaPem = jwkUtils.jwkToPem(rsaPublicKeyJwk)
    expect(generatedRsaPem, 'to equal', rsaPublicKey)
  })
})
