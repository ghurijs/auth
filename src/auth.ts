// authenticate / login / logout (Django's django.contrib.auth).
import {
  anonymousUser,
  ImproperlyConfigured,
  PermissionDenied,
  type RequestUser,
  rotateCsrfToken,
  setUser,
} from '@ghuri/core'
import type { Context } from 'hono'
import { type BaseBackend, type Credentials, getBackends, loadBackend } from './backends'
import type { AbstractBaseUser } from './models/auth'
import type { SessionBase } from './sessions/base'
import { userLoggedIn, userLoggedOut, userLoginFailed } from './signals'
import { getUserModel } from './user-model'
import { constantTimeCompare } from './utils/crypto'

export const SESSION_KEY = '_auth_user_id'
export const BACKEND_SESSION_KEY = '_auth_user_backend'
export const HASH_SESSION_KEY = '_auth_user_hash'
export const REDIRECT_FIELD_NAME = 'next'

declare module 'hono' {
  interface ContextVariableMap {
    session: SessionBase
  }
}

/** The request's session (requires `SessionMiddleware`). */
export function getSession(c: Context): SessionBase {
  const s = c.get('session') as SessionBase | undefined
  if (!s) {
    throw new ImproperlyConfigured(
      'No session on this request: add SessionMiddleware to MIDDLEWARE (before AuthenticationMiddleware).',
    )
  }
  return s
}

const SENSITIVE = /api|token|key|secret|password|signature/i

/** Credentials with sensitive values masked (for `userLoginFailed`). */
export function cleanseCredentials(credentials: Credentials): Credentials {
  const out: Credentials = {}
  for (const [k, v] of Object.entries(credentials)) out[k] = SENSITIVE.test(k) ? '********************' : v
  return out
}

/**
 * Try each backend in `AUTHENTICATION_BACKENDS`; returns the user (with `user.backend` set) or null.
 * A backend can stop the chain by throwing `PermissionDenied`.
 */
export async function authenticate(
  c: Context | undefined,
  credentials: Credentials,
): Promise<AbstractBaseUser | null> {
  for (const backend of getBackends()) {
    if (typeof backend.authenticate !== 'function') continue
    let user: AbstractBaseUser | null
    try {
      user = await backend.authenticate(c, credentials)
    } catch (err) {
      if (err instanceof PermissionDenied) break
      throw err
    }
    if (!user) continue
    Object.defineProperty(user, 'backend', {
      value: backend.backendName,
      writable: true,
      configurable: true,
      enumerable: false,
    })
    return user
  }
  await userLoginFailed.send('ghuri.auth', { credentials: cleanseCredentials(credentials), c })
  return null
}

function pkToString(user: AbstractBaseUser): string {
  return String(user.pk)
}

function backendFor(user: AbstractBaseUser, backend?: string | BaseBackend): string {
  if (backend) return typeof backend === 'string' ? backend : backend.backendName
  if (user.backend) return user.backend
  const loginBackends = getBackends().filter((b) => typeof b.getUser === 'function')
  if (loginBackends.length === 1) return loginBackends[0].backendName
  throw new TypeError(
    'You have multiple authentication backends configured and therefore must provide the `backend` argument or set the `backend` attribute on the user.',
  )
}

/**
 * Persist the user in the session (Django's `login()`): rotates the session key (or flushes another
 * user's session), stores id / backend / auth hash, rotates the CSRF token and sends `userLoggedIn`
 * (which updates `lastLogin`).
 */
export async function login(
  c: Context,
  user: AbstractBaseUser,
  backend?: string | BaseBackend,
): Promise<void> {
  const session = getSession(c)
  const hash = typeof user.getSessionAuthHash === 'function' ? await user.getSessionAuthHash() : ''
  if (await session.has(SESSION_KEY)) {
    const current = await session.get<string>(SESSION_KEY)
    const sessionHash = await session.get<string>(HASH_SESSION_KEY, '')
    if (current !== pkToString(user) || (hash && !constantTimeCompare(sessionHash ?? '', hash))) {
      await session.flush()
    }
  } else {
    await session.cycleKey()
  }
  await session.set(SESSION_KEY, pkToString(user))
  await session.set(BACKEND_SESSION_KEY, backendFor(user, backend))
  await session.set(HASH_SESSION_KEY, hash)
  setUser(c, user as unknown as RequestUser)
  try {
    rotateCsrfToken(c)
  } catch {
    // CSRF not configured on this context
  }
  await userLoggedIn.send(user.constructor, { c, user })
}

/** Remove the user from the session and flush it (Django's `logout()`). */
export async function logout(c: Context): Promise<void> {
  const current = c.get('user') as RequestUser | undefined
  const user = current?.isAuthenticated ? current : null
  await userLoggedOut.send(user ? (user as any).constructor : null, { c, user })
  const session = c.get('session') as SessionBase | undefined
  await session?.flush()
  setUser(c, anonymousUser)
}

/**
 * The user stored in the request's session, or `AnonymousUser` (Django's `get_user(request)`). Verifies
 * the session auth hash, so changing the password logs out other sessions.
 */
export async function getUserFromSession(c: Context): Promise<RequestUser> {
  const session = c.get('session') as SessionBase | undefined
  if (!session) return anonymousUser
  // No cookie → no stored session → no database access.
  if (session.sessionKey === null && session.isEmpty()) return anonymousUser
  const rawId = await session.get<string>(SESSION_KEY)
  const backendName = await session.get<string>(BACKEND_SESSION_KEY)
  if (rawId === undefined || backendName === undefined) return anonymousUser
  const backend = loadBackend(backendName)
  if (!backend?.getUser) return anonymousUser
  const User = getUserModel()
  let userId: unknown
  try {
    userId = User._meta.pk.toPython(rawId)
  } catch {
    return anonymousUser
  }
  const user = await backend.getUser(userId)
  if (!user) return anonymousUser
  if (typeof user.getSessionAuthHash === 'function') {
    const sessionHash = await session.get<string>(HASH_SESSION_KEY)
    let verified = !!sessionHash && constantTimeCompare(sessionHash, await user.getSessionAuthHash())
    if (!verified && sessionHash) {
      // A hash made with a SECRET_KEY_FALLBACKS key: accept and upgrade it.
      for (const fallback of await user.getSessionAuthFallbackHashes()) {
        if (constantTimeCompare(sessionHash, fallback)) {
          verified = true
          await session.cycleKey()
          await session.set(HASH_SESSION_KEY, await user.getSessionAuthHash())
          break
        }
      }
    }
    if (!verified) {
      await session.flush()
      return anonymousUser
    }
  }
  Object.defineProperty(user, 'backend', {
    value: backendName,
    writable: true,
    configurable: true,
    enumerable: false,
  })
  return user as unknown as RequestUser
}

/**
 * Keep the current session valid after a password change (Django's `update_session_auth_hash`): the
 * session key is rotated and the stored hash refreshed.
 */
export async function updateSessionAuthHash(c: Context, user: AbstractBaseUser): Promise<void> {
  const session = getSession(c)
  await session.cycleKey()
  const current = c.get('user') as RequestUser | undefined
  if (typeof user.getSessionAuthHash === 'function' && current && current.pk === user.pk) {
    await session.set(HASH_SESSION_KEY, await user.getSessionAuthHash())
  }
}

// `lastLogin` is updated by a signal receiver (disconnect `uid: 'ghuri.auth.updateLastLogin'` to opt out).
userLoggedIn.connect(
  async ({ user }) => {
    if (!user?.constructor?._meta?.getForwardField?.('lastLogin')) return
    user.lastLogin = new Date()
    if (!user._state?.adding) await user.save({ updateFields: ['lastLogin'] })
  },
  { uid: 'ghuri.auth.updateLastLogin' },
)
