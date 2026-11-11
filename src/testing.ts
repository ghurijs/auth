// Test client integration: client.forceLogin(user), client.login(credentials), client.logout().
import { registerTestClientHook, type TestClient } from '@ghuri/core/testing'
import { authenticate, BACKEND_SESSION_KEY, HASH_SESSION_KEY, SESSION_KEY } from './auth'
import { getBackends } from './backends'
import type { AbstractBaseUser } from './models/auth'
import { sessionConfig } from './sessions/base'
import { getSessionStoreClass } from './sessions/index'
import { userLoggedIn } from './signals'

async function storeLogin(client: TestClient, user: AbstractBaseUser, backend?: string): Promise<void> {
  await client.withContext(async (ctx) => {
    const config = sessionConfig(ctx.settings)
    const Store = getSessionStoreClass(config.engine)
    const current = client.getCookie(config.cookieName) ?? null
    const session = new Store(current, config)
    if (current) await session.cycleKey()
    else await session.create()
    const backendName =
      backend ??
      user.backend ??
      getBackends().find((b) => typeof b.getUser === 'function')?.backendName ??
      'ModelBackend'
    await session.set(SESSION_KEY, String(user.pk))
    await session.set(BACKEND_SESSION_KEY, backendName)
    await session.set(HASH_SESSION_KEY, await user.getSessionAuthHash())
    await session.save()
    await userLoggedIn.send(user.constructor, { c: undefined, user })
    client.setCookie(config.cookieName, session.sessionKey!)
  })
}

const KEY = Symbol.for('ghuri.auth.testHooks')
const g = globalThis as any
if (!g[KEY]) {
  g[KEY] = true
  registerTestClientHook(
    'forceLogin',
    async (client, user: AbstractBaseUser, opts?: { backend?: string }) => {
      await storeLogin(client, user, opts?.backend)
    },
  )
  registerTestClientHook('login', async (client, credentials: Record<string, unknown>) => {
    const user = await client.withContext(() => authenticate(undefined, credentials))
    if (!user) return false
    await storeLogin(client, user)
    return true
  })
  registerTestClientHook('logout', async (client) => {
    await client.withContext(async (ctx) => {
      const config = sessionConfig(ctx.settings)
      const key = client.getCookie(config.cookieName)
      if (!key) return
      const session = new (getSessionStoreClass(config.engine))(key, config)
      await session.flush()
    })
  })
}
