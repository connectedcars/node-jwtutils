import * as jwkUtils from './jwk-utils'
import { JwkBody } from './pubkeys-helper'
import {
  ecPublicKey,
  ecPublicKeyJwk,
  rsaPublicKey,
  rsaPublicKey4096,
  rsaPublicKey4096Jwk,
  rsaPublicKeyEncrypted,
  rsaPublicKeyEncryptedJwk,
  rsaPublicKeyJwk
} from './test-resources'

describe('jwkutils', () => {
  it('rsaPublicJwkToPem 1024bit', () => {
    const generatedPem = jwkUtils.rsaPublicJwkToPem(rsaPublicKeyJwk)
    expect(generatedPem).toEqual(rsaPublicKey)
  })
  it('rsaPublicJwkToPem 2048bit', () => {
    const generatedPem = jwkUtils.rsaPublicJwkToPem(rsaPublicKeyEncryptedJwk)
    expect(generatedPem).toEqual(rsaPublicKeyEncrypted)
  })
  it('rsaPublicJwkToPem 4096bit', () => {
    const generatedPem = jwkUtils.rsaPublicJwkToPem(rsaPublicKey4096Jwk)
    expect(generatedPem).toEqual(rsaPublicKey4096)
  })
  it('ecPublicJwkToPem K-256', () => {
    const generatedPem = jwkUtils.ecPublicKeyJwkToPem(ecPublicKeyJwk)
    expect(generatedPem).toEqual(ecPublicKey)
  })
  it('ecPublicJwkToPem P-256', () => {
    const jwk = {
      crv: 'P-256',
      kty: 'EC',
      x: 'gh9MmXjtmcHFesofqWZ6iuxSdAYgoPVvfJqpv1818lo',
      y: '3BDZHsNvKUb5VbyGPqcAFf4FGuPhJ2Xy215oWDw_1jc'
    } as JwkBody
    const expected =
      '-----BEGIN PUBLIC KEY-----\n' +
      'MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgh9MmXjtmcHFesofqWZ6iuxSdAYg\n' +
      'oPVvfJqpv1818lrcENkew28pRvlVvIY+pwAV/gUa4+EnZfLbXmhYPD/WNw==\n' +
      '-----END PUBLIC KEY-----'
    const generatedPem = jwkUtils.ecPublicKeyJwkToPem(jwk)
    expect(generatedPem).toEqual(expected)
  })
  it('ecPublicJwkToPem P-384', () => {
    const jwk = {
      crv: 'P-384',
      kty: 'EC',
      x: 'QIRvRhN2MpnTQ4teO4Y_RYFaK2Qlvc2lbhC0vALwrFOy33kUihkNUvHiTaUsp2W3',
      y: 'vSA1sCKKzT4UOavStUL2WpwcCflEyDshzy3dc1IZtACUngU2xMDDMsi0gDL9jLiU'
    } as JwkBody
    const expected =
      '-----BEGIN PUBLIC KEY-----\n' +
      'MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEQIRvRhN2MpnTQ4teO4Y/RYFaK2Qlvc2l\n' +
      'bhC0vALwrFOy33kUihkNUvHiTaUsp2W3vSA1sCKKzT4UOavStUL2WpwcCflEyDsh\n' +
      'zy3dc1IZtACUngU2xMDDMsi0gDL9jLiU\n' +
      '-----END PUBLIC KEY-----'
    const generatedPem = jwkUtils.ecPublicKeyJwkToPem(jwk)
    expect(generatedPem).toEqual(expected)
  })
  it('ecPublicJwkToPem P-521', () => {
    const jwk = {
      crv: 'P-521',
      kty: 'EC',
      x: 'AFqLf9vO672gS-Lv_BabqzKoedNLQgZkCemRZuzYu4KJjHgPBZ5fs3S05MoRXl4e7lR026XDDNPXawySVDXta9KF',
      y: 'APbUNzQ7IP_Mi0XwLN_RWZcIyHI43MJIAEn7O-KS0r8lvxjnVXeoopWAdqfTX_fCHXpYN1Ux1soOWujXb1uCEb7G'
    } as JwkBody
    const expected =
      '-----BEGIN PUBLIC KEY-----\n' +
      'MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAWot/287rvaBL4u/8FpurMqh500tC\n' +
      'BmQJ6ZFm7Ni7gomMeA8Fnl+zdLTkyhFeXh7uVHTbpcMM09drDJJUNe1r0oUA9tQ3\n' +
      'NDsg/8yLRfAs39FZlwjIcjjcwkgASfs74pLSvyW/GOdVd6iilYB2p9Nf98Idelg3\n' +
      'VTHWyg5a6NdvW4IRvsY=\n' +
      '-----END PUBLIC KEY-----'
    const generatedPem = jwkUtils.ecPublicKeyJwkToPem(jwk)
    expect(generatedPem).toEqual(expected)
  })
  it('jwkToPem K-256, RSA', () => {
    const generatedEcPem = jwkUtils.jwkToPem(ecPublicKeyJwk)
    expect(generatedEcPem).toEqual(ecPublicKey)
    const generatedRsaPem = jwkUtils.jwkToPem(rsaPublicKeyJwk)
    expect(generatedRsaPem).toEqual(rsaPublicKey)
  })
})
