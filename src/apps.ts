// App configs: contenttypes, auth, sessions, authtoken, token_blacklist.
import { AppConfig, apps, checks, ImproperlyConfigured, tryGetContext } from '@ghuri/core'
import * as orm from '@ghuri/orm'
import * as authMigrations from './auth/migrations/index'
import * as authtokenMigrations from './authtoken/migrations/index'
import { checkUserModel } from './checks'
import {
  ChangePasswordCommand,
  ClearSessionsCommand,
  CreateSuperuserCommand,
  CreateTokenCommand,
  FlushExpiredTokensCommand,
} from './commands'
import * as contenttypesMigrations from './contenttypes/migrations/index'
import { Group, Permission, User } from './models/auth'
import { ContentType } from './models/contenttypes'
import { Session } from './models/sessions'
import { BlacklistedToken, OutstandingToken, Token } from './models/tokens'
import { createPermissions } from './permissions'
import * as sessionsMigrations from './sessions/migrations/index'
import { migrationsForUserModel } from './swappable'
import * as tokenBlacklistMigrations from './token_blacklist/migrations/index'
import { DEFAULT_USER_MODEL, isUserModelSwapped } from './user-model'

/**
 * `AppConfig.path` of a bundled app: `src/<app>` when running from the TypeScript sources (the CLI,
 * `makemigrations`, tests), so migration files are read from and written to `src/<app>/migrations/`.
 * Undefined in the built package (`dist/` has no per-app directories: migrations are bundled and loaded
 * through `AppConfig.migrations`) and on Workers (no `import.meta.dirname`).
 */
function appPath(app: string): string | undefined {
  const meta = import.meta as ImportMeta & { dirname?: string; filename?: string }
  const dir = meta.dirname
  if (!dir || !/[\\/]src$/.test(dir) || !/\.[cm]?ts$/.test(meta.filename ?? '')) return undefined
  return `${dir}/${app}`
}

/**
 * `path` of an app whose migrations relate to the user model: undefined when `AUTH_USER_MODEL` is swapped,
 * so the CLI uses the adapted `migrations` (see `migrationsForUserModel`) instead of reading the files.
 */
function userModelAppPath(app: string): string | undefined {
  return tryGetContext() && isUserModelSwapped() ? undefined : appPath(app)
}

/** `contenttypes` app: `ContentType` (table `django_content_type`). Install it before `AuthConfig`. */
export class ContentTypesConfig extends AppConfig {
  name = '@ghuri/auth/contenttypes'
  override label = 'contenttypes'
  override verboseName = 'Content Types'
  override path = appPath('contenttypes')
  override migrations = contenttypesMigrations
  override models = { ContentType }
}

function authModels(): Record<string, unknown> {
  const label = tryGetContext()?.settings.AUTH_USER_MODEL as string | undefined
  const swapped = label !== undefined && label !== DEFAULT_USER_MODEL
  return swapped ? { Permission, Group } : { Permission, Group, User }
}

/** Run createPermissions after `migrate` (ORM `postMigrate` signal, when the ORM provides it). */
async function onPostMigrate(args: Record<string, any>): Promise<void> {
  const appConfig =
    args.appConfig ??
    args.app_config ??
    args.app ??
    (args.sender instanceof AppConfig ? args.sender : undefined)
  const using = args.using ?? args.database
  await createPermissions({ appConfig, using, verbosity: args.verbosity, stdout: args.stdout })
}

/**
 * `auth` app: `User` (unless `AUTH_USER_MODEL` swaps it), `Group`, `Permission`; commands
 * `createsuperuser` and `changepassword`. Requires `ContentTypesConfig`.
 */
export class AuthConfig extends AppConfig {
  name = '@ghuri/auth'
  override label = 'auth'
  override verboseName = 'Authentication and Authorization'
  override path = userModelAppPath('auth')
  override migrations = migrationsForUserModel('auth', authMigrations)
  override models = authModels()
  override commands = { createsuperuser: CreateSuperuserCommand, changepassword: ChangePasswordCommand }

  override ready(): void {
    if (!apps.isInstalled('contenttypes')) {
      throw new ImproperlyConfigured(
        "The 'auth' app requires 'contenttypes': add ContentTypesConfig to INSTALLED_APPS (before AuthConfig).",
      )
    }
    const postMigrate = (orm as Record<string, any>).postMigrate
    if (postMigrate && typeof postMigrate.connect === 'function') {
      postMigrate.connect(onPostMigrate, { uid: 'ghuri.auth.createPermissions' })
    }
    checks.register(checkUserModel)
  }
}

/** `sessions` app: `Session` (table `django_session`) for `SESSION_ENGINE: 'db'`; command `clearsessions`. */
export class SessionsConfig extends AppConfig {
  name = '@ghuri/auth/sessions'
  override label = 'sessions'
  override verboseName = 'Sessions'
  override path = appPath('sessions')
  override migrations = sessionsMigrations
  override models = { Session }
  override commands = { clearsessions: ClearSessionsCommand }
}

/** `authtoken` app (DRF's): `Token` (table `authtoken_token`); command `drf_create_token`. */
export class AuthTokenConfig extends AppConfig {
  name = '@ghuri/auth/authtoken'
  override label = 'authtoken'
  override verboseName = 'Auth Token'
  override path = userModelAppPath('authtoken')
  override migrations = migrationsForUserModel('authtoken', authtokenMigrations)
  override models = { Token }
  override commands = { drf_create_token: CreateTokenCommand }
}

/** `token_blacklist` app (simplejwt's): outstanding / blacklisted refresh tokens; `flushexpiredtokens`. */
export class TokenBlacklistConfig extends AppConfig {
  name = '@ghuri/auth/token_blacklist'
  override label = 'token_blacklist'
  override verboseName = 'Token Blacklist'
  override path = userModelAppPath('token_blacklist')
  override migrations = migrationsForUserModel('token_blacklist', tokenBlacklistMigrations)
  override models = { OutstandingToken, BlacklistedToken }
  override commands = { flushexpiredtokens: FlushExpiredTokensCommand }
}

/** The usual set: `[ContentTypesConfig, AuthConfig, SessionsConfig]` (spread into `INSTALLED_APPS`). */
export const authApps = [ContentTypesConfig, AuthConfig, SessionsConfig] as const
