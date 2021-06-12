// @flow
/* global fetch */
import EventEmitter from 'events'
import { authnFetch } from './authn-fetch'
import { openIdpPopup, obtainSession } from './popup'
import type { Session } from './session'
import { getSession, saveSession, clearSession } from './session'
import type { AsyncStorage } from './storage'
import { defaultStorage } from './storage'
import { toUrlString, currentUrlNoParams } from './url-util'
import * as WebIdOidc from './webid-oidc'

// Store the global fetch, so the user is free to override it
const globalFetch = fetch

export type loginOptions = {
  callbackUri: string,
  clientName?: string,
  contacts?: Array<string>,
  logoUri?: string,
  popupUri: string,
  storage: AsyncStorage,
}

export default class SolidAuthClient extends EventEmitter {
  _pendingSession: ?Promise<?Session>

  fetch(input: RequestInfo, options?: RequestOptions): Promise<Response> {
    this.emit('request', toUrlString(input))
    if (toUrlString(input).match(/^app/)) {
      if (
        typeof window.solid !== 'undefined' &&
        typeof window.solid.rest !== 'undefined'
      ) {
        return window.solid.rest.fetch(input, options)
      }
    }
    return authnFetch(defaultStorage(), globalFetch, input, options)
  }

  login(idp: string, options: loginOptions): Promise<?Session> {
    options = { ...defaultLoginOptions(currentUrlNoParams()), ...options }
    return WebIdOidc.login(idp, options)
  }

  async popupLogin(options: loginOptions): Promise<?Session> {
    options = { ...defaultLoginOptions(), ...options }
    if (!/https?:/.test(options.popupUri)) {
      options.popupUri = new URL(
        options.popupUri || '/.well-known/solid/login',
        window.location
      ).toString()
    }
    if (!options.callbackUri) {
      options.callbackUri = options.popupUri
    }
    const popup = openIdpPopup(options.popupUri)
    const session = await obtainSession(options.storage, popup, options)
    this.emit('login', session)
    this.emit('session', session)
    return session
  }

  async currentSession(
    storage: AsyncStorage = defaultStorage()
  ): Promise<?Session> {
    // Try to obtain a stored or pending session
    let session = this._pendingSession || (await getSession(storage))

    // If none found, attempt to create a new session
    if (!session) {
      // Try to create a new OIDC session from stored tokens
      try {
        this._pendingSession = WebIdOidc.currentSession(storage)
        session = await this._pendingSession
      } catch (err) {
        console.error(err)
      }

      // Save the new session and emit session events
      if (session) {
        await saveSession(storage)(session)
        this.emit('login', session)
        this.emit('session', session)
      }
      delete this._pendingSession
    }
    return session
  }

  async trackSession(callback: Function): Promise<void> {
    /* eslint-disable standard/no-callback-literal */
    callback(await this.currentSession())
    this.on('session', callback)
  }

  stopTrackSession(callback: Function): void {
    this.removeListener('session', callback)
  }

  async logout(storage: AsyncStorage = defaultStorage()): Promise<void> {
    const session = await getSession(storage)
    if (session) {
      try {
        await WebIdOidc.logout(storage, globalFetch)
        this.emit('logout')
        this.emit('session', null)
      } catch (err) {
        console.warn('Error logging out:')
        console.error(err)
      }
      await clearSession(storage)
    }
  }
}

function defaultLoginOptions(url: ?string): loginOptions {
  return {
    callbackUri: url ? url.split('#')[0] : '',
    popupUri: '',
    storage: defaultStorage(),
  }
}
