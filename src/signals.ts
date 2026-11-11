import { Signal } from '@ghuri/core'
import type { Context } from 'hono'

export interface UserLoggedInArgs {
  c: Context | undefined
  user: any
}
export interface UserLoggedOutArgs {
  c: Context | undefined
  user: any | null
}
export interface UserLoginFailedArgs {
  /** Credentials with sensitive values (password, token, key, secret…) masked. */
  credentials: Record<string, unknown>
  c: Context | undefined
}

function singleton<T>(key: string, create: () => T): T {
  const g = globalThis as any
  const sym = Symbol.for(key)
  if (!(sym in g)) g[sym] = create()
  return g[sym]
}

/** Sent by `login()` after a user logged in (sender: the user model class). */
export const userLoggedIn: Signal<UserLoggedInArgs> = singleton(
  'ghuri.auth.userLoggedIn',
  () => new Signal<UserLoggedInArgs>('userLoggedIn'),
)
/** Sent by `logout()` (sender: the user model class, or null for anonymous users). */
export const userLoggedOut: Signal<UserLoggedOutArgs> = singleton(
  'ghuri.auth.userLoggedOut',
  () => new Signal<UserLoggedOutArgs>('userLoggedOut'),
)
/** Sent by `authenticate()` when no backend accepted the credentials (sender: 'ghuri.auth'). */
export const userLoginFailed: Signal<UserLoginFailedArgs> = singleton(
  'ghuri.auth.userLoginFailed',
  () => new Signal<UserLoginFailedArgs>('userLoginFailed'),
)
