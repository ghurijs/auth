import { ImproperlyConfigured } from '@ghuri/core'
import type { SessionStoreClass } from './base'
import { DatabaseSessionStore } from './db'
import { CacheSessionStore, KVSessionStore } from './kv'
import { SignedCookieSessionStore } from './signed-cookie'

export * from './base'
export { DatabaseSessionStore } from './db'
export { CacheSessionStore, type KVNamespaceLike, KVSessionStore } from './kv'
export { SignedCookieSessionStore } from './signed-cookie'

/** `SESSION_ENGINE`: a built-in name or a `SessionBase` subclass. */
export type SessionEngine = 'db' | 'kv' | 'signedCookie' | 'cache' | SessionStoreClass

const ENGINES: Record<string, SessionStoreClass> = {
  db: DatabaseSessionStore,
  kv: KVSessionStore,
  signedCookie: SignedCookieSessionStore,
  signed_cookies: SignedCookieSessionStore,
  cache: CacheSessionStore,
}

/** Resolve `SESSION_ENGINE` to a store class. */
export function getSessionStoreClass(engine: unknown = 'db'): SessionStoreClass {
  if (typeof engine === 'function') return engine as SessionStoreClass
  const cls = ENGINES[String(engine)]
  if (!cls) {
    throw new ImproperlyConfigured(
      `Unknown SESSION_ENGINE '${String(engine)}' (use 'db', 'kv', 'signedCookie', 'cache' or a SessionBase subclass).`,
    )
  }
  return cls
}
