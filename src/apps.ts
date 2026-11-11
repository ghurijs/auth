// App configs: contenttypes, auth, sessions, authtoken, token_blacklist.
import { AppConfig, apps, checks, ImproperlyConfigured, tryGetContext } from '@ghuri/core'
import * as orm from '@ghuri/orm'
import { checkUserModel } from './checks'
import {
  ChangePasswordCommand,
  ClearSessionsCommand,
  CreateSuperuserCommand,
  CreateTokenCommand,
  FlushExpiredTokensCommand,
} from './commands'
import { Group, Permission, User } from './models/auth'
import { ContentType } from './models/contenttypes'
import { Session } from './models/sessions'
import { BlacklistedToken, OutstandingToken, Token } from './models/tokens'
import { createPermissions } from './permissions'
import { DEFAULT_USER_MODEL } from './user-model'

/** `contenttypes` app: `ContentType` (table `django_content_type`). Install it before `AuthConfig`. */
export class ContentTypesConfig extends AppConfig {
  name = '@ghuri/auth/contenttypes'
  override label = 'contenttypes'
  override verboseName = 'Content Types'
  override models = { ContentType }
}

function authModels(): Record<string, unknown> {
  const label = tryGetContext()?.settings.AUTH_USER_MODEL as string | undefined
  const swapped = label !== undefined && label !== DEFAULT_USER_MODEL
  return swapped ? { Permission, Group } : { Permission, Group, User }
}

/** Run createPermissions after `migrate` (ORM `postMigrate` signal, when the ORM provides it). */
async function onPostMigrate(args: Record<string, any>): Promise<void> {
  const appConfig = args.appConfig ?? args.app_config ?? args.app
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
  override models = { Session }
  override commands = { clearsessions: ClearSessionsCommand }
}

/** `authtoken` app (DRF's): `Token` (table `authtoken_token`); command `drf_create_token`. */
export class AuthTokenConfig extends AppConfig {
  name = '@ghuri/auth/authtoken'
  override label = 'authtoken'
  override verboseName = 'Auth Token'
  override models = { Token }
  override commands = { drf_create_token: CreateTokenCommand }
}

/** `token_blacklist` app (simplejwt's): outstanding / blacklisted refresh tokens; `flushexpiredtokens`. */
export class TokenBlacklistConfig extends AppConfig {
  name = '@ghuri/auth/token_blacklist'
  override label = 'token_blacklist'
  override verboseName = 'Token Blacklist'
  override models = { OutstandingToken, BlacklistedToken }
  override commands = { flushexpiredtokens: FlushExpiredTokensCommand }
}

/** The usual set: `[ContentTypesConfig, AuthConfig, SessionsConfig]` (spread into `INSTALLED_APPS`). */
export const authApps = [ContentTypesConfig, AuthConfig, SessionsConfig] as const
