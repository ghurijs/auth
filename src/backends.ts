// Authentication backends (Django's django.contrib.auth.backends).
import { ImproperlyConfigured, tryGetContext } from '@ghuri/core'
import type { Context } from 'hono'
import { type AbstractBaseUser, PERM_CACHE, Permission } from './models/auth'
import { getUserModel } from './user-model'

export type Credentials = Record<string, unknown>

/**
 * Backend interface. Every method is optional except `authenticate`/`getUser` for backends used to log in.
 * Permission methods receive the user instance.
 */
export abstract class BaseBackend {
  /**
   * Name stored in the session to find the backend again: the class's static `backendName` or, failing
   * that, the class name (set `static backendName` on custom backends — bundlers may minify class names).
   */
  get backendName(): string {
    return (this.constructor as { backendName?: string }).backendName ?? this.constructor.name
  }

  authenticate?(c: Context | undefined, credentials: Credentials): Promise<AbstractBaseUser | null>
  getUser?(userId: unknown): Promise<AbstractBaseUser | null>
  getUserPermissions?(user: any, obj?: unknown): Promise<Set<string>>
  getGroupPermissions?(user: any, obj?: unknown): Promise<Set<string>>
  getAllPermissions?(user: any, obj?: unknown): Promise<Set<string>>
  hasPerm?(user: any, perm: string, obj?: unknown): Promise<boolean>
  hasModulePerms?(user: any, appLabel: string): Promise<boolean>
}

interface PermCache {
  user?: Set<string>
  group?: Set<string>
  all?: Set<string>
}

function permCache(user: any): PermCache {
  let c = user[PERM_CACHE] as PermCache | undefined
  if (!c) {
    c = {}
    Object.defineProperty(user, PERM_CACHE, { value: c, configurable: true, enumerable: false })
  }
  return c
}

async function permStrings(qs: any): Promise<Set<string>> {
  const rows = (await qs.orderBy().valuesList('contentType__appLabel', 'codename')) as Array<[string, string]>
  return new Set(rows.map(([app, code]) => `${app}.${code}`))
}

/**
 * Authenticates against the user model (`USERNAME_FIELD` + password) and answers permission checks from
 * `userPermissions` and group permissions (cached on the user instance for the request).
 */
export class ModelBackend extends BaseBackend {
  static backendName = 'ModelBackend'
  async authenticate(_c: Context | undefined, credentials: Credentials): Promise<AbstractBaseUser | null> {
    const User = getUserModel()
    const username = credentials.username ?? credentials[User.USERNAME_FIELD]
    const password = credentials.password
    if (username === undefined || username === null || password === undefined || password === null)
      return null
    let user: AbstractBaseUser
    try {
      user = await User._defaultManager.get({ [User.USERNAME_FIELD]: username })
    } catch (err) {
      if (err instanceof User.DoesNotExist) {
        // Run the default hasher once to reduce the timing difference between existing and missing users.
        await new User().setPassword(String(password))
        return null
      }
      throw err
    }
    if ((await user.checkPassword(String(password))) && this.userCanAuthenticate(user)) return user
    return null
  }

  /** Reject users with `isActive = false` (custom models without the field are allowed). */
  userCanAuthenticate(user: any): boolean {
    return user?.isActive !== false
  }

  async getUser(userId: unknown): Promise<AbstractBaseUser | null> {
    const User = getUserModel()
    try {
      const user = await User._defaultManager.get({ pk: userId })
      return this.userCanAuthenticate(user) ? user : null
    } catch (err) {
      if (err instanceof User.DoesNotExist) return null
      throw err
    }
  }

  private async getPermissions(user: any, obj: unknown, kind: 'user' | 'group'): Promise<Set<string>> {
    if (!user || user.isActive === false || user.isAnonymous || (obj !== undefined && obj !== null))
      return new Set()
    const cache = permCache(user)
    if (cache[kind]) return cache[kind]!
    let perms: Set<string>
    const meta = (user.constructor as any)._meta
    if (user.isSuperuser) {
      perms = await permStrings(Permission.objects.all())
    } else if (kind === 'user') {
      perms = meta.getForwardField('userPermissions')
        ? await permStrings(Permission.objects.filter({ user: user.pk }))
        : new Set()
    } else {
      perms = meta.getForwardField('groups')
        ? await permStrings(Permission.objects.filter({ group__user: user.pk }))
        : new Set()
    }
    cache[kind] = perms
    return perms
  }

  getUserPermissions(user: any, obj?: unknown): Promise<Set<string>> {
    return this.getPermissions(user, obj, 'user')
  }

  getGroupPermissions(user: any, obj?: unknown): Promise<Set<string>> {
    return this.getPermissions(user, obj, 'group')
  }

  async getAllPermissions(user: any, obj?: unknown): Promise<Set<string>> {
    if (!user || user.isActive === false || user.isAnonymous || (obj !== undefined && obj !== null))
      return new Set()
    const cache = permCache(user)
    if (!cache.all) {
      cache.all = new Set([
        ...(await this.getUserPermissions(user)),
        ...(await this.getGroupPermissions(user)),
      ])
    }
    return cache.all
  }

  async hasPerm(user: any, perm: string, obj?: unknown): Promise<boolean> {
    return user?.isActive !== false && (await this.getAllPermissions(user, obj)).has(perm)
  }

  async hasModulePerms(user: any, appLabel: string): Promise<boolean> {
    if (user?.isActive === false) return false
    for (const p of await this.getAllPermissions(user))
      if (p.slice(0, p.indexOf('.')) === appLabel) return true
    return false
  }
}

/** `ModelBackend` that also lets inactive users log in. */
export class AllowAllUsersModelBackend extends ModelBackend {
  static backendName = 'AllowAllUsersModelBackend'
  override userCanAuthenticate(_user: any): boolean {
    return true
  }
}

/**
 * Trusts a username supplied by the web server / proxy (`RemoteUserMiddleware`), creating unknown users
 * (`createUnknownUser`).
 */
export class RemoteUserBackend extends ModelBackend {
  static backendName = 'RemoteUserBackend'
  createUnknownUser = true

  override async authenticate(
    c: Context | undefined,
    credentials: Credentials,
  ): Promise<AbstractBaseUser | null> {
    const remoteUser = credentials.remoteUser
    if (typeof remoteUser !== 'string' || !remoteUser) return null
    const User = getUserModel()
    const username = this.cleanUsername(remoteUser)
    let user: AbstractBaseUser | null = null
    if (this.createUnknownUser) {
      const [u, created] = await User._defaultManager.getOrCreate({ [User.USERNAME_FIELD]: username })
      if (created) {
        u.setUnusablePassword()
        await u.save()
      }
      user = await this.configureUser(c, u, created)
    } else {
      try {
        user = await User._defaultManager.get({ [User.USERNAME_FIELD]: username })
      } catch (err) {
        if (!(err instanceof User.DoesNotExist)) throw err
      }
    }
    return user && this.userCanAuthenticate(user) ? user : null
  }

  /** Hook to normalize the remote username (e.g. strip a realm). */
  cleanUsername(username: string): string {
    return username
  }

  /** Hook to configure users (set groups, flags…). */
  async configureUser(
    _c: Context | undefined,
    user: AbstractBaseUser,
    _created: boolean,
  ): Promise<AbstractBaseUser> {
    return user
  }
}

export class AllowAllUsersRemoteUserBackend extends RemoteUserBackend {
  static backendName = 'AllowAllUsersRemoteUserBackend'
  override userCanAuthenticate(_user: any): boolean {
    return true
  }
}

// ---- configured backends ------------------------------------------------------------------------------

type BackendEntry = (new () => BaseBackend) | BaseBackend

const cache = new WeakMap<object, BaseBackend[]>()
let defaults: BaseBackend[] | undefined

/** Instances of `AUTHENTICATION_BACKENDS` (default `[ModelBackend]`). */
export function getBackends(): BaseBackend[] {
  const configured = tryGetContext()?.settings.AUTHENTICATION_BACKENDS as BackendEntry[] | undefined
  if (!configured) {
    defaults ??= [new ModelBackend()]
    return defaults
  }
  let list = cache.get(configured)
  if (!list) {
    if (!configured.length) {
      throw new ImproperlyConfigured(
        'No authentication backends have been defined. Does AUTHENTICATION_BACKENDS contain anything?',
      )
    }
    list = configured.map((b) => (typeof b === 'function' ? new b() : b))
    cache.set(configured, list)
  }
  return list
}

/** Find a configured backend by the name stored in the session. */
export function loadBackend(name: string): BaseBackend | undefined {
  const all = getBackends()
  const found = all.find((b) => b.backendName === name)
  if (found) return found
  // Class names can change between minified builds; with a single login backend, use it.
  const login = all.filter((b) => typeof b.getUser === 'function')
  return login.length === 1 ? login[0] : undefined
}
