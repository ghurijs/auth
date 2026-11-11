import { caches, ImproperlyConfigured, tryGetContext } from '@ghuri/core'
import { CreateError } from '../errors'
import { createWithNewKey, SessionBase, type SessionData } from './base'

/** The subset of a Workers KV namespace the session store uses. */
export interface KVNamespaceLike {
  get(key: string): Promise<string | null>
  put(key: string, value: string, opts?: { expirationTtl?: number }): Promise<void>
  delete(key: string): Promise<void>
}

/** KV requires TTLs of at least 60 seconds. */
const KV_MIN_TTL = 60

/**
 * `SESSION_ENGINE: 'kv'` — sessions in Workers KV (binding `SESSION_KV_BINDING`, default `SESSIONS`).
 * Fast reads at the edge; KV is eventually consistent (a write may take up to ~60 s to reach other
 * locations), so prefer `db` when a session must be visible everywhere immediately.
 */
export class KVSessionStore extends SessionBase {
  static keyPrefix = 'ghuri.session:'

  protected get kv(): KVNamespaceLike {
    const env = tryGetContext()?.env ?? {}
    const ns = env[this.config.kvBinding] as KVNamespaceLike | undefined
    if (!ns || typeof ns.get !== 'function') {
      throw new ImproperlyConfigured(
        `SESSION_ENGINE 'kv' needs a Workers KV binding named '${this.config.kvBinding}' (SESSION_KV_BINDING).`,
      )
    }
    return ns
  }

  protected kvKey(key: string): string {
    return (this.constructor as typeof KVSessionStore).keyPrefix + key
  }

  async exists(sessionKey: string): Promise<boolean> {
    return (await this.kv.get(this.kvKey(sessionKey))) !== null
  }

  protected async load(): Promise<SessionData> {
    const raw = await this.kv.get(this.kvKey(this._sessionKey!))
    if (raw === null) {
      this._sessionKey = null
      return {}
    }
    return this.decode(raw)
  }

  async create(): Promise<void> {
    await createWithNewKey(this)
  }

  async save(mustCreate = false): Promise<void> {
    if (this._sessionKey === null) return this.create()
    if (mustCreate && (await this.exists(this._sessionKey))) throw new CreateError('Session key collision')
    const data = await this.session(mustCreate)
    const ttl = Math.max(KV_MIN_TTL, await this.getExpiryAge())
    await this.kv.put(this.kvKey(this._sessionKey), await this.encode(data), { expirationTtl: ttl })
  }

  async deleteSession(sessionKey: string | null = this._sessionKey): Promise<void> {
    if (!sessionKey) return
    await this.kv.delete(this.kvKey(sessionKey))
  }
}

/** `SESSION_ENGINE: 'cache'` — sessions in a core cache (`SESSION_CACHE_ALIAS`, default `'default'`). */
export class CacheSessionStore extends SessionBase {
  static keyPrefix = 'ghuri.contrib.sessions.cache'

  protected get cache() {
    return caches.get(this.config.cacheAlias)
  }

  protected cacheKey(key: string): string {
    return (this.constructor as typeof CacheSessionStore).keyPrefix + key
  }

  async exists(sessionKey: string): Promise<boolean> {
    return (await this.cache.get(this.cacheKey(sessionKey))) !== undefined
  }

  protected async load(): Promise<SessionData> {
    const raw = await this.cache.get<string>(this.cacheKey(this._sessionKey!))
    if (raw === undefined || raw === null) {
      this._sessionKey = null
      return {}
    }
    return this.decode(raw)
  }

  async create(): Promise<void> {
    await createWithNewKey(this)
  }

  async save(mustCreate = false): Promise<void> {
    if (this._sessionKey === null) return this.create()
    const data = await this.session(mustCreate)
    const key = this.cacheKey(this._sessionKey)
    const value = await this.encode(data)
    const ttl = await this.getExpiryAge()
    if (mustCreate) {
      const added = await this.cache.add(key, value, ttl)
      if (!added) throw new CreateError('Session key collision')
    } else {
      await this.cache.set(key, value, ttl)
    }
  }

  async deleteSession(sessionKey: string | null = this._sessionKey): Promise<void> {
    if (!sessionKey) return
    await this.cache.delete(this.cacheKey(sessionKey))
  }
}
