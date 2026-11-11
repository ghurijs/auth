// Session stores (Django's django.contrib.sessions.backends.base.SessionBase), async.
import { type GhuriSettings, tryGetContext } from '@ghuri/core'
import { CreateError } from '../errors'
import { BadSignature, dumps, loads } from '../signing'
import { getRandomString } from '../utils/crypto'

export const VALID_KEY_CHARS = 'abcdefghijklmnopqrstuvwxyz0123456789'

/** Session settings resolved from `GhuriSettings` (Django names and defaults). */
export interface SessionConfig {
  engine: unknown
  cookieName: string
  cookieAge: number
  cookieDomain?: string
  cookiePath: string
  cookieSecure: boolean
  cookieHttpOnly: boolean
  cookieSameSite: 'Lax' | 'Strict' | 'None' | false
  saveEveryRequest: boolean
  expireAtBrowserClose: boolean
  kvBinding: string
  cacheAlias: string
}

export function sessionConfig(
  settings: Partial<GhuriSettings> | undefined = tryGetContext()?.settings,
): SessionConfig {
  const s = settings ?? {}
  return {
    engine: s.SESSION_ENGINE ?? 'db',
    cookieName: s.SESSION_COOKIE_NAME ?? 'sessionid',
    cookieAge: s.SESSION_COOKIE_AGE ?? 60 * 60 * 24 * 7 * 2,
    cookieDomain: s.SESSION_COOKIE_DOMAIN ?? undefined,
    cookiePath: s.SESSION_COOKIE_PATH ?? '/',
    cookieSecure: s.SESSION_COOKIE_SECURE ?? false,
    cookieHttpOnly: s.SESSION_COOKIE_HTTPONLY ?? true,
    cookieSameSite: s.SESSION_COOKIE_SAMESITE === undefined ? 'Lax' : s.SESSION_COOKIE_SAMESITE,
    saveEveryRequest: s.SESSION_SAVE_EVERY_REQUEST ?? false,
    expireAtBrowserClose: s.SESSION_EXPIRE_AT_BROWSER_CLOSE ?? false,
    kvBinding: s.SESSION_KV_BINDING ?? 'SESSIONS',
    cacheAlias: s.SESSION_CACHE_ALIAS ?? 'default',
  }
}

export type SessionData = Record<string, unknown>

const EXPIRY_KEY = '_session_expiry'

/**
 * Base class of session stores. `c.get('session')` is one of these. Data methods are async because the
 * session is loaded lazily from its store on first access.
 *
 * ```ts
 * const session = c.get('session')
 * await session.set('cart', [1, 2])
 * const cart = await session.get('cart', [])
 * await session.cycleKey()
 * ```
 */
export abstract class SessionBase {
  /** Salt for signing session payloads (Django's `"django.contrib.sessions." + qualname`). */
  static keySalt = 'django.contrib.sessions.SessionStore'

  /** True once data was read or written. */
  accessed = false
  /** True once data changed (the middleware then saves the session). */
  modified = false
  readonly config: SessionConfig
  protected _sessionKey: string | null = null
  protected _cache: SessionData | null = null

  constructor(sessionKey: string | null = null, config: SessionConfig = sessionConfig()) {
    this.config = config
    this._sessionKey = this.validateKey(sessionKey) ? sessionKey : null
  }

  // ---- key handling ----

  get sessionKey(): string | null {
    return this._sessionKey
  }

  protected validateKey(key: string | null | undefined): key is string {
    return typeof key === 'string' && key.length >= 8
  }

  protected setSessionKey(key: string | null): void {
    this._sessionKey = this.validateKey(key) ? key : null
  }

  /** A new random key (32 chars of a-z0-9) not used yet by the store. */
  protected async getNewSessionKey(): Promise<string> {
    for (;;) {
      const key = getRandomString(32, VALID_KEY_CHARS)
      if (!(await this.exists(key))) return key
    }
  }

  // ---- encoding ----

  get keySalt(): string {
    return (this.constructor as typeof SessionBase).keySalt
  }

  /** Signed (and compressed) JSON, Django's session encoding. */
  encode(data: SessionData): Promise<string> {
    return dumps(data, { salt: this.keySalt, compress: true })
  }

  /** Decode a stored payload; tampered/undecodable data yields an empty session. */
  async decode(data: string): Promise<SessionData> {
    try {
      return (await loads<SessionData>(data, { salt: this.keySalt })) ?? {}
    } catch (err) {
      if (!(err instanceof BadSignature)) console.warn('Session data corrupted:', err)
      return {}
    }
  }

  // ---- data ----

  /** Loaded session data (loads from the store on first access). */
  protected async session(noLoad = false): Promise<SessionData> {
    this.accessed = true
    if (this._cache === null) {
      this._cache = this._sessionKey === null || noLoad ? {} : await this.load()
    }
    return this._cache
  }

  async get<T = unknown>(key: string, fallback?: T): Promise<T> {
    const s = await this.session()
    return (key in s ? s[key] : fallback) as T
  }

  async set(key: string, value: unknown): Promise<void> {
    const s = await this.session()
    s[key] = value
    this.modified = true
  }

  async has(key: string): Promise<boolean> {
    return key in (await this.session())
  }

  /** Remove a key; returns whether it existed. */
  async delete(key: string): Promise<boolean> {
    const s = await this.session()
    if (!(key in s)) return false
    delete s[key]
    this.modified = true
    return true
  }

  async pop<T = unknown>(key: string, fallback?: T): Promise<T> {
    const s = await this.session()
    if (!(key in s)) return fallback as T
    const v = s[key]
    delete s[key]
    this.modified = true
    return v as T
  }

  async setDefault<T = unknown>(key: string, value: T): Promise<T> {
    const s = await this.session()
    if (key in s) return s[key] as T
    s[key] = value
    this.modified = true
    return value
  }

  async update(values: SessionData): Promise<void> {
    Object.assign(await this.session(), values)
    this.modified = true
  }

  async keys(): Promise<string[]> {
    return Object.keys(await this.session())
  }

  async items(): Promise<Array<[string, unknown]>> {
    return Object.entries(await this.session())
  }

  /** A copy of all data. */
  async toObject(): Promise<SessionData> {
    return { ...(await this.session()) }
  }

  /** Remove all data (the key stays). */
  async clear(): Promise<void> {
    this._cache = {}
    this.accessed = true
    this.modified = true
  }

  /** No key and nothing loaded/set. */
  isEmpty(): boolean {
    return !this._sessionKey && (this._cache === null || Object.keys(this._cache).length === 0)
  }

  // ---- expiry ----

  /** Seconds until expiry (from `_session_expiry` or `SESSION_COOKIE_AGE`). */
  async getExpiryAge(
    opts: { modification?: Date; expiry?: number | string | Date | null } = {},
  ): Promise<number> {
    const modification = opts.modification ?? new Date()
    const expiry =
      opts.expiry !== undefined ? opts.expiry : await this.get<number | string | null>(EXPIRY_KEY)
    if (!expiry) return this.config.cookieAge
    if (typeof expiry === 'number') return expiry
    const date = expiry instanceof Date ? expiry : new Date(expiry)
    return Math.floor((date.getTime() - modification.getTime()) / 1000)
  }

  /** Expiry date of the session. */
  async getExpiryDate(
    opts: { modification?: Date; expiry?: number | string | Date | null } = {},
  ): Promise<Date> {
    const modification = opts.modification ?? new Date()
    const expiry =
      opts.expiry !== undefined ? opts.expiry : await this.get<number | string | null>(EXPIRY_KEY)
    if (expiry instanceof Date) return expiry
    if (typeof expiry === 'string') return new Date(expiry)
    const age = expiry || this.config.cookieAge
    return new Date(modification.getTime() + age * 1000)
  }

  /**
   * Set the expiry: seconds of inactivity (`0` = when the browser closes), a `Date`, or `null` to fall
   * back to the global policy.
   */
  async setExpiry(value: number | Date | null): Promise<void> {
    if (value === null) {
      await this.delete(EXPIRY_KEY)
      return
    }
    await this.set(EXPIRY_KEY, value instanceof Date ? value.toISOString() : value)
  }

  /** Does the session expire when the browser closes? */
  async getExpireAtBrowserClose(): Promise<boolean> {
    const expiry = await this.get(EXPIRY_KEY, null)
    if (expiry === null || expiry === undefined) return this.config.expireAtBrowserClose
    return expiry === 0
  }

  // ---- lifecycle ----

  /** Delete the session data and key (logout). */
  async flush(): Promise<void> {
    await this.clear()
    await this.deleteSession()
    this._sessionKey = null
  }

  /** Keep the data, change the key (login: prevents session fixation). */
  async cycleKey(): Promise<void> {
    const data = await this.session()
    const key = this._sessionKey
    await this.create()
    this._cache = data
    if (key) await this.deleteSession(key)
  }

  // ---- store API (implemented by engines) ----

  /** Does a session with this key exist in the store? */
  abstract exists(sessionKey: string): Promise<boolean>
  /** Create a new, empty session with a fresh key (and save it). */
  abstract create(): Promise<void>
  /** Persist the session. `mustCreate` fails with `CreateError` if the key exists. */
  abstract save(mustCreate?: boolean): Promise<void>
  /** Delete a session from the store (default: this one). */
  abstract deleteSession(sessionKey?: string | null): Promise<void>
  /** Load the data for `this.sessionKey` (empty object + key reset if missing/expired). */
  protected abstract load(): Promise<SessionData>

  /** Remove expired sessions (where the store needs it). */
  static async clearExpired(): Promise<void> {}
}

/** Shared create() loop for key-value stores. */
export async function createWithNewKey(
  store: SessionBase & { save(mustCreate?: boolean): Promise<void> },
): Promise<void> {
  for (;;) {
    ;(store as any)._sessionKey = await (store as any).getNewSessionKey()
    try {
      await store.save(true)
    } catch (err) {
      if (err instanceof CreateError) continue
      throw err
    }
    store.modified = true
    return
  }
}

export type SessionStoreClass = (new (
  sessionKey?: string | null,
  config?: SessionConfig,
) => SessionBase) & {
  clearExpired(): Promise<void>
}
