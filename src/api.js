// @flow
/* global RequestInfo, Response */
import { authnFetch } from './authn-fetch'
import { currentUrlNoParams } from './browser-util'
import type { session } from './session'
import { getSession, saveSession, clearSession } from './session'
import type { AsyncStorage } from './storage'
import { defaultStorage } from './storage'
import * as WebIdTls from './webid-tls'
import * as WebIdOidc from './webid-oidc'

export type authResponse =
  { session: ?session
  , fetch: (url: RequestInfo, options?: Object) => Promise<Response>
  }

export type loginOptions = {
  redirectUri: ?string,
  storage: AsyncStorage
}

const defaultLoginOptions = (): loginOptions => {
  const url = currentUrlNoParams()
  return {
    redirectUri: url ? url.split('#')[0] : null,
    storage: defaultStorage()
  }
}

export const fetch = (url: RequestInfo, options?: Object): Promise<Response> =>
  authnFetch(defaultStorage())(url, options)

const responseFromFirstSession = async (storage: AsyncStorage, authFns: Array<() => Promise<?session>>): Promise<authResponse> => {
  if (authFns.length === 0) {
    return { session: null, fetch: authnFetch(storage) }
  }
  const session = await authFns[0]()
  if (session) {
    try {
      return { session: await saveSession(storage)(session), fetch: authnFetch(storage) }
    } catch (err) {
      console.error(err)
    }
  }
  return responseFromFirstSession(storage, authFns.slice(1))
}

export const login = (idp: string, options: loginOptions): Promise<authResponse> => {
  options = { ...defaultLoginOptions(), ...options }
  return responseFromFirstSession(options.storage, [
    WebIdTls.login.bind(null, idp),
    WebIdOidc.login.bind(null, idp, options)
  ])
}

export const currentSession = async (storage: AsyncStorage = defaultStorage()): Promise<authResponse> => {
  const session = await getSession(storage)
  if (session) {
    return { session, fetch: authnFetch(storage) }
  }
  return responseFromFirstSession(storage, [
    WebIdOidc.currentSession.bind(null, storage)
  ])
}

export const logout = async (storage: AsyncStorage = defaultStorage()): Promise<void> => {
  try {
    const session = await getSession(storage)
    if (session && session.idToken && session.accessToken) {
      await WebIdOidc.logout(storage)
    }
    await clearSession(storage)
  } catch (err) {
    console.warn('Error logging out:')
    console.error(err)
  }
}
