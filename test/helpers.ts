import {
  createApp,
  createContext,
  CsrfMiddleware,
  defineSettings,
  type Env,
  type GhuriSettings,
  type UrlPatterns,
} from '@ghuri/core'
import { createTestClient } from '@ghuri/core/testing'
import { setupTestDatabase, type TestBackend } from '@ghuri/orm/testing'
import {
  AuthConfig,
  AuthenticationMiddleware,
  AuthTokenConfig,
  ContentType,
  ContentTypesConfig,
  PBKDF2PasswordHasher,
  SessionMiddleware,
  SessionsConfig,
  TokenBlacklistConfig,
} from '../src/index'

/** Fast hasher for tests (production default is 100,000 iterations). */
export const FAST_HASHERS = [new PBKDF2PasswordHasher({ iterations: 1000 })]

export const SECRET = 'test-secret-key'

/** In-memory stand-in for a Workers KV namespace. */
export function memoryKV() {
  const store = new Map<string, { value: string; ttl?: number }>()
  return {
    store,
    async get(key: string) {
      return store.get(key)?.value ?? null
    },
    async put(key: string, value: string, opts?: { expirationTtl?: number }) {
      store.set(key, { value, ttl: opts?.expirationTtl })
    },
    async delete(key: string) {
      store.delete(key)
    },
  }
}

export const ALL_APPS = [ContentTypesConfig, AuthConfig, SessionsConfig, AuthTokenConfig, TokenBlacklistConfig]

export interface AuthAppOptions {
  using?: TestBackend
  settings?: Partial<GhuriSettings>
  urls?: UrlPatterns
  env?: Env
}

/** createApp + app.setup + setupTestDatabase + a test client sharing one env. */
export async function setupAuthApp(opts: AuthAppOptions = {}) {
  const env: Env = opts.env ?? { SESSIONS: memoryKV() }
  const settings = defineSettings(() => ({
    SECRET_KEY: SECRET,
    INSTALLED_APPS: ALL_APPS,
    MIDDLEWARE: [SessionMiddleware, CsrfMiddleware, AuthenticationMiddleware],
    ROOT_URLCONF: opts.urls ?? [],
    PASSWORD_HASHERS: FAST_HASHERS,
    ...opts.settings,
  }))
  const app = createApp(settings)
  const ctx = await app.setup(env)
  const db = await setupTestDatabase({ using: opts.using ?? 'sqlite' })
  const client = createTestClient(app, { env })
  return {
    app,
    env,
    ctx,
    db,
    client,
    async flush() {
      await db.flush()
      ContentType.objects.clearCache()
      client.clearCookies()
    },
  }
}

/** A bare context (no DB) for unit tests of settings-dependent helpers. */
export function bareContext(settings: Partial<GhuriSettings> = {}) {
  return createContext({
    env: {},
    settings: { SECRET_KEY: SECRET, INSTALLED_APPS: [], ROOT_URLCONF: [], ...settings } as GhuriSettings,
  })
}
