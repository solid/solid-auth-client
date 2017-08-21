/* eslint-env mocha */
/* global expect */
import fs from 'fs'
import jwt from 'jsonwebtoken'
import nock from 'nock'
import rsaPemToJwk from 'rsa-pem-to-jwk'
import URLSearchParams from 'url-search-params'

import { currentSession, fetch, login, logout } from './api'
import { saveHost } from './hosts'
import { LocalStorage } from './storage'
import { getSession, saveSession } from './session'

/*
 * OIDC test data:
 *   1) the oidc configuration returned from '/.well-known/openid-configuration'
 *   2) the registration response
 *   3) the json web key set
 */

const oidcConfiguration = {
  issuer: 'https://localhost',
  jwks_uri: 'https://localhost/jwks',
  registration_endpoint: 'https://localhost/register',
  authorization_endpoint: 'https://localhost/authorize',
  end_session_endpoint: 'https://localhost/logout'
}

const oidcRegistration = {
  client_id: 'the-client-id'
}

const pem = fs.readFileSync('./test-keys/id_rsa')

const jwks = {
  keys: [
    rsaPemToJwk(
      // the PEM-encoded key
      pem,
      // extra data for the JWK
      { kid: '1', alg: 'RS256', use: 'sig', key_ops: [ 'verify' ] },
      // serialize just the public key
      'public'
    )
  ]
}

const storage = new LocalStorage()

let _href
let _URL

// polyfill missing/incomplete web apis
beforeEach(() => {
  _href = window.location.href
  Object.defineProperty(window.location, 'href', {
    writable: true,
    value: 'https://app.biz/'
  })
  Object.defineProperty(window.location, 'origin', {
    writable: true,
    value: 'https://app.biz'
  })
  Object.defineProperty(window.location, 'pathname', {
    writable: true,
    value: '/'
  })
  _URL = window.URL
  window.URL = function (urlStr) {
    const url = new _URL(urlStr)
    url.searchParams = new URLSearchParams(url.search)
    return url
  }
  window.URLSearchParams = URLSearchParams
  const store = {}
  window.localStorage = {
    length: 0,
    key: (i) => Object.keys(store)[i],
    getItem: (key) => key in store ? store[key] : null,
    setItem: (key, val) => {
      if (!(key in store)) {
        window.localStorage.length++
      }
      store[key] = val
    }
  }
})

afterEach(() => {
  delete window.localStorage
  delete window.URLSearchParams
  window.URL = _URL
  window.location.href = _href
})

describe('login', () => {
  beforeEach(() => {
    nock.disableNetConnect()
  })

  afterEach(() => {
    nock.cleanAll()
    nock.enableNetConnect()
  })

  it('returns an anonymous auth response when no recognized auth scheme is present', async () => {
    nock('https://localhost')
      .head('/')
      .reply(200)
      .get('/.well-known/openid-configuration')
      .reply(404)

    const { session } = await login('https://localhost')
    expect(session).toBeNull()
    expect(await getSession(storage)).toBeNull()
  })

  describe('WebID-TLS', () => {
    it('can log in with WebID-TLS', async () => {
      const webId = 'https://localhost/profile#me'
      nock('https://localhost/')
        .head('/')
        .reply(200, '', { user: webId })

      const { session } = await login('https://localhost')
      expect(session.webId).toBe(webId)
      expect(await getSession(storage)).toEqual(session)
    })
  })

  describe('WebID-OIDC', () => {
    it('can log in with WebID-OIDC', async () => {
      nock('https://localhost/')
        // try to log in with WebID-TLS
        .head('/')
        .reply(200)
        // no user header, so try to use WebID-OIDC
        .get('/.well-known/openid-configuration')
        .reply(200, oidcConfiguration)
        .get('/jwks')
        .reply(200, jwks)
        .post('/register')
        .reply(200, oidcRegistration)

      await login('https://localhost')
      const location = new window.URL(window.location.href)
      expect(location.origin).toEqual('https://localhost')
      expect(location.pathname).toEqual('/authorize')
      expect(location.searchParams.get('redirect_uri')).toEqual('https://app.biz/')
      expect(location.searchParams.get('response_type')).toEqual('id_token token')
      expect(location.searchParams.get('scope')).toEqual('openid')
      expect(location.searchParams.get('client_id')).toEqual('the-client-id')
    })

    it('uses the provided redirect uri', async () => {
      nock('https://localhost')
        // try to log in with WebID-TLS
        .head('/')
        .reply(200)
        // no user header, so try to use WebID-OIDC
        .get('/.well-known/openid-configuration')
        .reply(200, oidcConfiguration)
        .get('/jwks')
        .reply(200, jwks)
        .post('/register')
        .reply(200, oidcRegistration)

      await login('https://localhost', { redirectUri: 'https://app.biz/welcome/' })
      const location = new window.URL(window.location.href)
      expect(location.origin).toEqual('https://localhost')
      expect(location.pathname).toEqual('/authorize')
      expect(location.searchParams.get('redirect_uri')).toEqual('https://app.biz/welcome/')
      expect(location.searchParams.get('response_type')).toEqual('id_token token')
      expect(location.searchParams.get('scope')).toEqual('openid')
      expect(location.searchParams.get('client_id')).toEqual('the-client-id')
    })

    it('strips the hash fragment from the current URL when proiding the default redirect URL', async () => {
      nock('https://localhost/')
        // try to log in with WebID-TLS
        .head('/')
        .reply(200)
        // no user header, so try to use WebID-OIDC
        .get('/.well-known/openid-configuration')
        .reply(200, oidcConfiguration)
        .get('/jwks')
        .reply(200, jwks)
        .post('/register')
        .reply(200, oidcRegistration)

      window.location.href += '#foo-bar'

      await login('https://localhost')
      const location = new window.URL(window.location.href)
      expect(location.origin).toEqual('https://localhost')
      expect(location.pathname).toEqual('/authorize')
      expect(location.searchParams.get('redirect_uri')).toEqual('https://app.biz/')
      expect(location.searchParams.get('response_type')).toEqual('id_token token')
      expect(location.searchParams.get('scope')).toEqual('openid')
      expect(location.searchParams.get('client_id')).toEqual('the-client-id')
    })

    // TODO: this is broken due to https://github.com/anvilresearch/oidc-rp/issues/26
    it('resolves to a `null` session when none of the recognized auth schemes are available')
  })
})

describe('currentSession', () => {
  it('can find the current session if stored', async () => {
    await saveSession(storage)({
      authType: 'WebID-OIDC',
      idp: 'https://localhost',
      webId: 'https://person.me/#me',
      accessToken: 'fake_access_token',
      idToken: 'abc.def.ghi'
    })

    const { session } = await currentSession()
    expect(session.webId).toBe('https://person.me/#me')
    expect(await getSession(storage)).toEqual(session)
  })

  it('resolves to a `null` session when there is no stored session or OIDC response', async () => {
    const { session } = await currentSession()
    expect(session).toBeNull()
    expect(await getSession(storage)).toBeNull()
  })

  describe('WebID-OIDC', () => {
    it('can find the current session from the URL auth response', async () => {
      // To test currentSession with WebID-OIDC it's easist to set up the OIDC RP
      // client by logging in, generating the IDP's response, and redirecting
      // back to the app.
      nock('https://localhost/')
        // try to log in with WebID-TLS
        .head('/')
        .reply(200)
        // no user header, so try to use WebID-OIDC
        .get('/.well-known/openid-configuration')
        .reply(200, oidcConfiguration)
        .get('/jwks')
        .reply(200, jwks)
        .post('/register')
        .reply(200, oidcRegistration)
        // see https://github.com/anvilresearch/oidc-rp/issues/29
        .get('/jwks')
        .reply(200, jwks)

      let expectedIdToken, expectedAccessToken

      await login('https://localhost')
      // generate the auth response
      const location = new window.URL(window.location.href)
      const state = location.searchParams.get('state')
      const redirectUri = location.searchParams.get('redirect_uri')
      const nonce = location.searchParams.get('nonce')
      const accessToken = 'example_access_token'
      const { alg } = jwks.keys[0]
      const idToken = jwt.sign(
        {
          iss: oidcConfiguration.issuer,
          aud: oidcRegistration.client_id,
          exp: Math.floor(Date.now() / 1000) + (60 * 60), // one hour
          sub: 'https://person.me/#me',
          nonce
        },
        pem,
        { algorithm: alg }
      )
      expectedIdToken = idToken
      expectedAccessToken = accessToken
      window.location.href = `${redirectUri}#` +
        `access_token=${accessToken}&` +
        `token_type=Bearer&` +
        `id_token=${idToken}&` +
        `state=${state}`

      const { session } = await currentSession()
      expect(session.webId).toBe('https://person.me/#me')
      expect(session.accessToken).toBe(expectedAccessToken)
      expect(session.idToken).toBe(expectedIdToken)
      expect(await getSession(storage)).toEqual(session)
      expect(window.location.hash).toBe('')
    })
  })
})

describe('logout', () => {
  describe('WebID-TLS', () => {
    it('just removes the current session from the store', async () => {
      await saveSession(storage)({
        authType: 'WebID-TLS',
        idp: 'https://localhost',
        webId: 'https://person.me/#me'
      })

      await logout()
      expect(await getSession(storage)).toBeNull()
    })
  })

  describe('WebID-OIDC', () => {
    it('hits the end_session_endpoint and clears the current session from the store', async () => {
      // To test currentSession with WebID-OIDC it's easist to set up the OIDC RP
      // client by logging in, generating the IDP's response, and redirecting
      // back to the app.
      nock('https://localhost/')
        // try to log in with WebID-TLS
        .head('/')
        .reply(200)
        // no user header, so try to use WebID-OIDC
        .get('/.well-known/openid-configuration')
        .reply(200, oidcConfiguration)
        .get('/jwks')
        .reply(200, jwks)
        .post('/register')
        .reply(200, oidcRegistration)
        // no luck, try with WebID-OIDC
        // see https://github.com/anvilresearch/oidc-rp/issues/29
        .get('/jwks')
        .reply(200, jwks)
        .get('/logout')
        .reply(200)

      let expectedIdToken, expectedAccessToken

      await login('https://localhost')
      // generate the auth response
      const location = new window.URL(window.location.href)
      const state = location.searchParams.get('state')
      const redirectUri = location.searchParams.get('redirect_uri')
      const nonce = location.searchParams.get('nonce')
      const accessToken = 'example_access_token'
      const { alg } = jwks.keys[0]
      const idToken = jwt.sign(
        {
          iss: oidcConfiguration.issuer,
          aud: oidcRegistration.client_id,
          exp: Math.floor(Date.now() / 1000) + (60 * 60), // one hour
          sub: 'https://person.me/#me',
          nonce
        },
        pem,
        { algorithm: alg }
      )
      expectedIdToken = idToken
      expectedAccessToken = accessToken
      window.location.href = `${redirectUri}#` +
        `access_token=${accessToken}&` +
        `token_type=Bearer&` +
        `id_token=${idToken}&` +
        `state=${state}`

      const { session } = await currentSession()
      expect(session.webId).toBe('https://person.me/#me')
      expect(session.accessToken).toBe(expectedAccessToken)
      expect(session.idToken).toBe(expectedIdToken)
      expect(window.location.hash).toBe('')
      expect(await getSession(storage)).toEqual(session)

      await logout()
      expect(await getSession(storage)).toBeNull()
    })
  })
})

describe('fetch', () => {
  it('handles 401s from WebID-OIDC resources by resending with credentials', async () => {
    await saveSession(storage)({
      authType: 'WebID-OIDC',
      idp: 'https://localhost',
      webId: 'https://person.me/#me',
      accessToken: 'fake_access_token',
      idToken: 'abc.def.ghi'
    })

    nock('https://third-party.com')
      .get('/protected-resource')
      .reply(401, '', { 'www-authenticate': 'Bearer scope="openid webid"' })
      .get('/protected-resource')
      .matchHeader('authorization', 'Bearer abc.def.ghi')
      .reply(200)

    const resp = await fetch('https://third-party.com/protected-resource')
    expect(resp.status).toBe(200)
  })

  it('merges request headers with the authorization header', async () => {
    await saveSession(storage)({
      authType: 'WebID-OIDC',
      idp: 'https://localhost',
      webId: 'https://person.me/#me',
      accessToken: 'fake_access_token',
      idToken: 'abc.def.ghi'
    })

    nock('https://third-party.com')
      .get('/private-resource')
      .reply(401, '', { 'www-authenticate': 'Bearer scope="openid webid"' })
      .get('/private-resource')
      .matchHeader('accept', 'text/plain')
      .matchHeader('authorization', 'Bearer abc.def.ghi')
      .reply(200)

    const resp = await fetch('https://third-party.com/private-resource', { headers: { accept: 'text/plain' } })
    expect(resp.status).toBe(200)
  })

  it('does not resend with credentials if the www-authenticate header is missing', async () => {
    await saveSession(storage)({
      authType: 'WebID-OIDC',
      idp: 'https://localhost',
      webId: 'https://person.me/#me',
      accessToken: 'fake_access_token',
      idToken: 'abc.def.ghi'
    })

    nock('https://third-party.com')
      .get('/protected-resource')
      .reply(401)

    const resp = await fetch('https://third-party.com/protected-resource')
    expect(resp.status).toBe(401)
  })

  it('does not resend with credentials if the www-authenticate header suggests an unknown scheme', async () => {
    await saveSession(storage)({
      authType: 'WebID-OIDC',
      idp: 'https://localhost',
      webId: 'https://person.me/#me',
      accessToken: 'fake_access_token',
      idToken: 'abc.def.ghi'
    })

    nock('https://third-party.com')
      .get('/protected-resource')
      .reply(401, '', { 'www-authenticate': 'Basic token' })

    const resp = await fetch('https://third-party.com/protected-resource')
    expect(resp.status).toBe(401)
  })

  it('does not resend with credentials if there is no session', async () => {
    nock('https://third-party.com')
      .get('/protected-resource')
      .reply(401, '', { 'www-authenticate': 'Bearer scope="openid webid"' })

    const resp = await fetch('https://third-party.com/protected-resource')
    expect(resp.status).toBe(401)
  })

  it('does not resend with credentials if the requested resource is public', async () => {
    nock('https://third-party.com')
      .get('/public-resource')
      .reply(200, 'public content', { 'content-type': 'text/plain' })

    const resp = await fetch('https://third-party.com/public-resource')
    expect(resp.status).toBe(200)
    const body = await resp.text()
    expect(body).toEqual('public content')
  })

  it('does not resend with credentials if the requested resources uses plain OIDC', async () => {
    nock('https://third-party.com')
      .get('/protected-resource')
      .reply(401, '', { 'www-authenticate': 'Bearer scope="openid"' })

    const resp = await fetch('https://third-party.com/protected-resource')
    expect(resp.status).toBe(401)
  })

  describe('familiar domains with WebID-OIDC', () => {
    it('just sends one request when the RP is also the IDP', async () => {
      await saveSession(storage)({
        authType: 'WebID-OIDC',
        idp: 'https://localhost',
        webId: 'https://person.me/#me',
        accessToken: 'fake_access_token',
        idToken: 'abc.def.ghi'
      })

      nock('https://localhost')
        .get('/resource')
        .matchHeader('authorization', 'Bearer abc.def.ghi')
        .reply(200)

      const resp = await fetch('https://localhost/resource')
      expect(resp.status).toBe(200)
    })

    it('just sends one request to domains it has already encountered', async () => {
      await saveSession(storage)({
        authType: 'WebID-OIDC',
        idp: 'https://localhost',
        webId: 'https://person.me/#me',
        accessToken: 'fake_access_token',
        idToken: 'abc.def.ghi'
      })

      saveHost(storage)({
        url: 'third-party.com',
        authType: 'WebID-OIDC'
      })

      nock('https://third-party.com')
        .get('/resource')
        .matchHeader('authorization', 'Bearer abc.def.ghi')
        .reply(200)

      const resp = await fetch('https://third-party.com/resource')
      expect(resp.status).toBe(200)
    })

    it('does not send credentials to a familiar domain when that domain uses a different auth type', async () => {
      await saveSession(storage)({
        authType: 'WebID-OIDC',
        idp: 'https://localhost',
        webId: 'https://person.me/#me',
        accessToken: 'fake_access_token',
        idToken: 'abc.def.ghi'
      })

      saveHost(storage)({
        url: 'third-party.com',
        authType: 'WebID-TLS'
      })

      nock('https://third-party.com')
        .get('/resource')
        .reply(401)

      const resp = await fetch('https://third-party.com/resource')
      expect(resp.status).toBe(401)
    })
  })
})
