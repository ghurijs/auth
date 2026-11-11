import { type GhuriSettings, tryGetContext } from '@ghuri/core'
import type { BaseBackend } from './backends'
import type { BasePasswordHasher } from './hashers'
import type { JWTSettings } from './jwt'
import type { PasswordValidatorConfig } from './password-validation'
import type { SessionEngine } from './sessions/index'

declare module '@ghuri/core' {
  interface GhuriSettings {
    /** `'app_label.ModelName'` of the user model (default `'auth.User'`). */
    AUTH_USER_MODEL?: string
    /** Authentication backends: classes or instances (default `[ModelBackend]`). */
    AUTHENTICATION_BACKENDS?: Array<(new () => BaseBackend) | BaseBackend>
    /** Password hashers, preferred first (classes or instances). */
    PASSWORD_HASHERS?: Array<(new () => BasePasswordHasher) | BasePasswordHasher>
    /** Password validators (`[{ NAME: MinimumLengthValidator, OPTIONS: { minLength: 9 } }]`). */
    AUTH_PASSWORD_VALIDATORS?: PasswordValidatorConfig[]
    /** Old secret keys still accepted for signatures, session hashes and reset tokens. */
    SECRET_KEY_FALLBACKS?: string[]
    LOGIN_URL?: string
    LOGIN_REDIRECT_URL?: string
    LOGOUT_REDIRECT_URL?: string | null
    /** Seconds a password reset link stays valid (default 3 days). */
    PASSWORD_RESET_TIMEOUT?: number
    // Sessions (Django names and defaults)
    SESSION_ENGINE?: SessionEngine
    SESSION_COOKIE_NAME?: string
    SESSION_COOKIE_AGE?: number
    SESSION_COOKIE_DOMAIN?: string | null
    SESSION_COOKIE_PATH?: string
    SESSION_COOKIE_SECURE?: boolean
    SESSION_COOKIE_HTTPONLY?: boolean
    SESSION_COOKIE_SAMESITE?: 'Lax' | 'Strict' | 'None' | false
    SESSION_SAVE_EVERY_REQUEST?: boolean
    SESSION_EXPIRE_AT_BROWSER_CLOSE?: boolean
    /** Workers KV binding used by the `kv` session engine (default `'SESSIONS'`). */
    SESSION_KV_BINDING?: string
    /** Cache alias used by the `cache` session engine (default `'default'`). */
    SESSION_CACHE_ALIAS?: string
    /** Header read by `RemoteUserMiddleware` (default `'Remote-User'`). */
    REMOTE_USER_HEADER?: string
    /** JWT settings (djangorestframework-simplejwt names). `SIMPLE_JWT` is accepted as an alias. */
    JWT?: JWTSettings
  }
}

/** Current settings, or undefined outside a Ghuri context. */
export function currentSettings(): GhuriSettings | undefined {
  return tryGetContext()?.settings
}

/** Read a setting with a fallback (works outside a context too). */
export function authSetting<K extends keyof GhuriSettings>(
  name: K,
  fallback: NonNullable<GhuriSettings[K]>,
): NonNullable<GhuriSettings[K]> {
  const v = currentSettings()?.[name]
  return (v === undefined || v === null ? fallback : v) as NonNullable<GhuriSettings[K]>
}

export const DEFAULT_LOGIN_URL = '/accounts/login/'
export const DEFAULT_LOGIN_REDIRECT_URL = '/accounts/profile/'
export const DEFAULT_PASSWORD_RESET_TIMEOUT = 60 * 60 * 24 * 3
