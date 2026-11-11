// django.contrib.auth.models: Permission, Group, AbstractBaseUser, PermissionsMixin, AbstractUser, User.
import { PermissionDenied, ValidationError } from '@ghuri/core'
import {
  BooleanField,
  CASCADE,
  CharField,
  DateTimeField,
  EmailField,
  ForeignKey,
  Manager,
  ManyToManyField,
  Model,
  type ModelClass,
  Q,
  type SaveOptions,
} from '@ghuri/orm'
import { checkPassword, isPasswordUsable, makePassword, makeUnusablePassword } from '../hashers'
import { passwordChanged } from '../password-validation'
import { bytesToHex, getSecretKeyFallbacks, saltedHmac } from '../utils/crypto'
import { ContentType } from './contenttypes'

// ---- Permission / Group ------------------------------------------------------------------------------

export class PermissionManager extends Manager<Permission> {
  /** `getByNaturalKey('add_post', 'blog', 'post')`. */
  getByNaturalKey(codename: string, appLabel: string, model: string): Promise<Permission> {
    return this.get({ codename, contentType__appLabel: appLabel, contentType__model: model })
  }
}

/** A permission: `codename` on a model's content type (`'blog.add_post'`). */
export class Permission extends Model({
  name: new CharField({ maxLength: 255, verboseName: 'name' }),
  contentType: new ForeignKey(() => ContentType, { onDelete: CASCADE, verboseName: 'content type' }),
  codename: new CharField({ maxLength: 100, verboseName: 'codename' }),
}) {
  static Meta = {
    verboseName: 'permission',
    verboseNamePlural: 'permissions',
    uniqueTogether: [['contentType', 'codename']],
    ordering: ['contentType__appLabel', 'contentType__model', 'codename'],
  }
  static objects = new PermissionManager()

  naturalKey(): [string, string, string] | [string] {
    const ct = this._state.fieldsCache.get('contentType') as ContentType | undefined
    return ct ? [this.codename, ct.appLabel, ct.model] : [this.codename]
  }

  override toString(): string {
    const ct = this._state.fieldsCache.get('contentType') as ContentType | undefined
    return ct ? `${ct.toString()} | ${this.name}` : this.name
  }
}

export class GroupManager extends Manager<Group> {
  getByNaturalKey(name: string): Promise<Group> {
    return this.get({ name })
  }
}

/** A named set of permissions. Users in the group get its permissions. */
export class Group extends Model({
  name: new CharField({ maxLength: 150, unique: true, verboseName: 'name' }),
  permissions: new ManyToManyField(() => Permission, { blank: true, verboseName: 'permissions' }),
}) {
  static Meta = { verboseName: 'group', verboseNamePlural: 'groups' }
  static objects = new GroupManager()

  naturalKey(): [string] {
    return [this.name]
  }

  override toString(): string {
    return this.name
  }
}

// ---- username validators ------------------------------------------------------------------------------

/** Letters, digits and `@ . + - _` (Unicode letters allowed). Django's `UnicodeUsernameValidator`. */
export const unicodeUsernameValidator = {
  message: 'Enter a valid username. This value may contain only letters, numbers, and @/./+/-/_ characters.',
  validate(value: unknown): void {
    if (typeof value !== 'string' || !/^[\p{L}\p{M}\p{N}_.@+-]+$/u.test(value)) {
      throw new ValidationError(this.message, { code: 'invalid' })
    }
  },
}

/** ASCII-only variant (Django's `ASCIIUsernameValidator`). */
export const asciiUsernameValidator = {
  message:
    'Enter a valid username. This value may contain only unaccented lowercase a-z and uppercase A-Z letters, numbers, and @/./+/-/_ characters.',
  validate(value: unknown): void {
    if (typeof value !== 'string' || !/^[A-Za-z0-9_.@+-]+$/.test(value)) {
      throw new ValidationError(this.message, { code: 'invalid' })
    }
  },
}

// ---- managers -----------------------------------------------------------------------------------------

/** Lower-case the domain part of an email address (Django's `normalize_email`). */
export function normalizeEmail(email: string | null | undefined): string {
  const e = (email ?? '').trim()
  const at = e.lastIndexOf('@')
  if (at < 0) return e
  return `${e.slice(0, at)}@${e.slice(at + 1).toLowerCase()}`
}

/** Static side of user model classes. */
export interface UserModelStatics {
  USERNAME_FIELD: string
  EMAIL_FIELD: string
  REQUIRED_FIELDS: string[]
  normalizeUsername(username: string): string
  getEmailFieldName(): string
}

export type UserModelClass<U extends AbstractBaseUser = AbstractBaseUser> = ModelClass<U> &
  UserModelStatics & { objects: BaseUserManager<U> }

type CreateUserData = Record<string, unknown> & { password?: string | null }

/** Django's `BaseUserManager`: natural-key lookup and helpers for custom managers. */
export class BaseUserManager<U extends AbstractBaseUser = any> extends Manager<U> {
  /** Lower-case the domain part of an email address. */
  normalizeEmail(email: string | null | undefined): string {
    return normalizeEmail(email)
  }

  protected get userModel(): UserModelClass<U> {
    this.assertBound()
    return this.model as unknown as UserModelClass<U>
  }

  /** Look a user up by `USERNAME_FIELD`. */
  getByNaturalKey(username: unknown): Promise<U> {
    return this.get({ [this.userModel.USERNAME_FIELD]: username } as Record<string, unknown> as any)
  }

  /** A random string (e.g. for temporary passwords). */
  makeRandomPassword(
    length = 10,
    allowedChars = 'abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789',
  ): string {
    const bytes = new Uint8Array(length * 2)
    crypto.getRandomValues(bytes)
    let out = ''
    for (const b of bytes) {
      if (out.length >= length) break
      if (b < 256 - (256 % allowedChars.length)) out += allowedChars[b % allowedChars.length]
    }
    return out.length < length ? out + this.makeRandomPassword(length - out.length, allowedChars) : out
  }
}

/**
 * Django's `UserManager`, generalized to any `USERNAME_FIELD`:
 *
 * ```ts
 * await User.objects.createUser('ann', 'ann@example.com', 's3cret!', { firstName: 'Ann' })
 * await User.objects.createUser({ username: 'ann', email: 'ann@example.com', password: 's3cret!' })
 * await User.objects.createSuperuser('admin', 'admin@example.com', 's3cret!')
 * ```
 */
export class UserManager<U extends AbstractBaseUser = any> extends BaseUserManager<U> {
  private normalizeArgs(
    usernameOrData: unknown,
    email?: string | null,
    password?: string | null,
    extra: Record<string, unknown> = {},
  ): CreateUserData {
    const M = this.userModel
    if (usernameOrData && typeof usernameOrData === 'object') return { ...(usernameOrData as CreateUserData) }
    const data: CreateUserData = { ...extra, [M.USERNAME_FIELD]: usernameOrData, password }
    if (email !== undefined && M.EMAIL_FIELD !== M.USERNAME_FIELD) data[M.EMAIL_FIELD] = email
    return data
  }

  protected async _createUser(data: CreateUserData): Promise<U> {
    const M = this.userModel
    const { password, ...fields } = data
    const uf = M.USERNAME_FIELD
    if (!fields[uf]) throw new TypeError(`The given ${uf} must be set`)
    if (typeof fields[uf] === 'string') {
      fields[uf] =
        uf === M.EMAIL_FIELD
          ? this.normalizeEmail(fields[uf] as string)
          : M.normalizeUsername(fields[uf] as string)
    }
    const ef = M.EMAIL_FIELD
    if (ef !== uf && M._meta.getForwardField(ef))
      fields[ef] = this.normalizeEmail(fields[ef] as string | null)
    const user = new M(fields)
    user.password =
      password === null || password === undefined ? makeUnusablePassword() : await makePassword(password)
    await user.save({ using: this.getQueryset().db })
    return user
  }

  /** `createUser(username, email?, password?, extraFields?)` or `createUser({ ...fields, password })`. */
  async createUser(
    usernameOrData: unknown,
    email?: string | null,
    password?: string | null,
    extraFields: Record<string, unknown> = {},
  ): Promise<U> {
    const data = this.normalizeArgs(usernameOrData, email, password, extraFields)
    if (this.userModel._meta.getForwardField('isStaff')) data.isStaff ??= false
    if (this.userModel._meta.getForwardField('isSuperuser')) data.isSuperuser ??= false
    return this._createUser(data)
  }

  /** Like `createUser` with `isStaff` and `isSuperuser` set (both must stay true). */
  async createSuperuser(
    usernameOrData: unknown,
    email?: string | null,
    password?: string | null,
    extraFields: Record<string, unknown> = {},
  ): Promise<U> {
    const data = this.normalizeArgs(usernameOrData, email, password, extraFields)
    const meta = this.userModel._meta
    if (meta.getForwardField('isStaff')) {
      data.isStaff ??= true
      if (data.isStaff !== true) throw new TypeError('Superuser must have isStaff=true.')
    }
    if (meta.getForwardField('isSuperuser')) {
      data.isSuperuser ??= true
      if (data.isSuperuser !== true) throw new TypeError('Superuser must have isSuperuser=true.')
    }
    return this._createUser(data)
  }

  /**
   * Users having `perm` (`'app.codename'` or a Permission) through their own permissions or groups, plus
   * superusers (`includeSuperusers`, default true). Only `ModelBackend` semantics are supported.
   */
  withPerm(perm: string | Permission, opts: { isActive?: boolean; includeSuperusers?: boolean } = {}) {
    const isActive = opts.isActive ?? true
    const includeSuperusers = opts.includeSuperusers ?? true
    let permQ: ReturnType<typeof Q>
    if (typeof perm === 'string') {
      const [appLabel, codename] = perm.split('.', 2)
      if (!codename) throw new TypeError("The permission should be in the form 'app_label.codename'.")
      permQ = Q({
        groups__permissions__codename: codename,
        groups__permissions__contentType__appLabel: appLabel,
      }).or(Q({ userPermissions__codename: codename, userPermissions__contentType__appLabel: appLabel }))
    } else {
      permQ = Q({ groups__permissions: perm.pk }).or(Q({ userPermissions: perm.pk }))
    }
    let q = permQ
    if (includeSuperusers) q = q.or(Q({ isSuperuser: true }))
    let qs = this.filter(q)
    if (isActive !== null && this.userModel._meta.getForwardField('isActive')) qs = qs.filter({ isActive })
    return qs
  }
}

// ---- user models --------------------------------------------------------------------------------------

const PERM_CACHE = Symbol.for('ghuri.auth.permCache')

/** Lazy import of the backends (avoids a module cycle). */
async function backends() {
  return (await import('../backends')).getBackends()
}

const SESSION_HASH_SALT = 'django.contrib.auth.models.AbstractBaseUser.get_session_auth_hash'

/**
 * Minimal user: `password` and `lastLogin`, password helpers and permission checks delegated to
 * `AUTHENTICATION_BACKENDS`. Extend it for a fully custom user model (set `USERNAME_FIELD`).
 */
export class AbstractBaseUser extends Model({
  password: new CharField({ maxLength: 128, verboseName: 'password' }),
  lastLogin: new DateTimeField({ null: true, blank: true, verboseName: 'last login' }),
}) {
  static Meta = { abstract: true }
  static USERNAME_FIELD = 'username'
  static EMAIL_FIELD = 'email'
  static REQUIRED_FIELDS: string[] = []
  static objects = new UserManager()

  /** Raw password set by `setPassword()` until the next save (for validators' `passwordChanged`). */
  declare _password?: string | null
  /** Backend that authenticated this user (set by `authenticate()`). */
  declare backend?: string

  /** NFKC-normalize a username (Django's `normalize_username`). */
  static normalizeUsername(username: string): string {
    return typeof username === 'string' ? username.normalize('NFKC') : username
  }

  static getEmailFieldName(): string {
    // biome-ignore lint/complexity/noThisInStatic: subclasses override EMAIL_FIELD
    return this.EMAIL_FIELD ?? 'email'
  }

  get isAuthenticated(): boolean {
    return true
  }

  get isAnonymous(): boolean {
    return false
  }

  /** The value of `USERNAME_FIELD`. */
  getUsername(): string {
    return (this as any)[(this.constructor as unknown as UserModelStatics).USERNAME_FIELD]
  }

  naturalKey(): [string] {
    return [this.getUsername()]
  }

  override clean(): void | Promise<void> {
    const M = this.constructor as unknown as UserModelStatics
    const v = (this as any)[M.USERNAME_FIELD]
    if (typeof v === 'string') (this as any)[M.USERNAME_FIELD] = M.normalizeUsername(v)
  }

  override async save(opts?: SaveOptions): Promise<void> {
    await super.save(opts)
    if (this._password !== undefined && this._password !== null) {
      const raw = this._password
      this._password = null
      await passwordChanged(raw, this)
    }
  }

  /** Hash and set the password (not saved). `null` sets an unusable password. */
  async setPassword(raw: string | null): Promise<void> {
    this.password = await makePassword(raw)
    Object.defineProperty(this, '_password', {
      value: raw,
      writable: true,
      configurable: true,
      enumerable: false,
    })
  }

  /** Check a raw password; re-hashes and saves when the stored hash uses outdated parameters. */
  checkPassword(raw: string): Promise<boolean> {
    const setter = async (pw: string) => {
      await this.setPassword(pw)
      this._password = null
      if (!this._state.adding) await this.save({ updateFields: ['password'] })
    }
    return checkPassword(raw, this.password, setter)
  }

  setUnusablePassword(): void {
    this.password = makeUnusablePassword()
  }

  hasUsablePassword(): boolean {
    return isPasswordUsable(this.password)
  }

  /** HMAC of the password hash: sessions are invalidated when the password changes. */
  async getSessionAuthHash(secret?: string): Promise<string> {
    return bytesToHex(await saltedHmac(SESSION_HASH_SALT, this.password, secret, 'sha256'))
  }

  /** Session hashes for each of `SECRET_KEY_FALLBACKS`. */
  async getSessionAuthFallbackHashes(): Promise<string[]> {
    const out: string[] = []
    for (const key of getSecretKeyFallbacks()) out.push(await this.getSessionAuthHash(key))
    return out
  }

  // ---- permissions (delegated to AUTHENTICATION_BACKENDS) ----

  /** Superusers that are active have every permission. */
  protected get isActiveSuperuser(): boolean {
    return (this as any).isActive !== false && (this as any).isSuperuser === true
  }

  async getUserPermissions(obj?: unknown): Promise<Set<string>> {
    const out = new Set<string>()
    for (const b of await backends())
      if (b.getUserPermissions) for (const p of await b.getUserPermissions(this, obj)) out.add(p)
    return out
  }

  async getGroupPermissions(obj?: unknown): Promise<Set<string>> {
    const out = new Set<string>()
    for (const b of await backends())
      if (b.getGroupPermissions) for (const p of await b.getGroupPermissions(this, obj)) out.add(p)
    return out
  }

  async getAllPermissions(obj?: unknown): Promise<Set<string>> {
    const out = new Set<string>()
    for (const b of await backends())
      if (b.getAllPermissions) for (const p of await b.getAllPermissions(this, obj)) out.add(p)
    return out
  }

  /** `await user.hasPerm('blog.add_post')`. Active superusers always pass. */
  async hasPerm(perm: string, obj?: unknown): Promise<boolean> {
    if (this.isActiveSuperuser) return true
    for (const b of await backends()) {
      if (!b.hasPerm) continue
      try {
        if (await b.hasPerm(this, perm, obj)) return true
      } catch (err) {
        if (err instanceof PermissionDenied) return false
        throw err
      }
    }
    return false
  }

  async hasPerms(perms: Iterable<string>, obj?: unknown): Promise<boolean> {
    if (typeof perms === 'string') throw new TypeError('perms must be an iterable of permissions.')
    for (const p of perms) if (!(await this.hasPerm(p, obj))) return false
    return true
  }

  /** Does the user have any permission in `appLabel`? */
  async hasModulePerms(appLabel: string): Promise<boolean> {
    if (this.isActiveSuperuser) return true
    for (const b of await backends()) {
      if (!b.hasModulePerms) continue
      try {
        if (await b.hasModulePerms(this, appLabel)) return true
      } catch (err) {
        if (err instanceof PermissionDenied) return false
        throw err
      }
    }
    return false
  }

  /** Drop the per-instance permission cache (after changing groups / permissions). */
  clearPermCache(): void {
    delete (this as any)[PERM_CACHE]
  }
}

/** Field set of Django's `PermissionsMixin` (for spreading into custom field maps). */
export const permissionsMixinFields = () => ({
  isSuperuser: new BooleanField({
    default: false,
    verboseName: 'superuser status',
    helpText: 'Designates that this user has all permissions without explicitly assigning them.',
  }),
  groups: new ManyToManyField(() => Group, {
    blank: true,
    relatedName: 'userSet',
    relatedQueryName: 'user',
    verboseName: 'groups',
    helpText:
      'The groups this user belongs to. A user will get all permissions granted to each of their groups.',
  }),
  userPermissions: new ManyToManyField(() => Permission, {
    blank: true,
    relatedName: 'userSet',
    relatedQueryName: 'user',
    verboseName: 'user permissions',
    helpText: 'Specific permissions for this user.',
  }),
})

/**
 * `AbstractBaseUser` + Django's `PermissionsMixin` fields (`isSuperuser`, `groups`, `userPermissions`).
 * Model inheritance is linear in Ghuri, so the mixin already includes the base user.
 */
export class PermissionsMixin extends Model(permissionsMixinFields(), { extends: AbstractBaseUser }) {
  static Meta = { abstract: true }
}

/** Django's `AbstractUser`: username, names, email, staff/active flags, dateJoined + permissions. */
export class AbstractUser extends Model(
  {
    username: new CharField({
      maxLength: 150,
      unique: true,
      verboseName: 'username',
      helpText: 'Required. 150 characters or fewer. Letters, digits and @/./+/-/_ only.',
      validators: [unicodeUsernameValidator],
      errorMessages: { unique: 'A user with that username already exists.' },
    }),
    firstName: new CharField({ maxLength: 150, blank: true, verboseName: 'first name' }),
    lastName: new CharField({ maxLength: 150, blank: true, verboseName: 'last name' }),
    email: new EmailField({ maxLength: 254, blank: true, verboseName: 'email address' }),
    isStaff: new BooleanField({
      default: false,
      verboseName: 'staff status',
      helpText: 'Designates whether the user can log into this admin site.',
    }),
    isActive: new BooleanField({
      default: true,
      verboseName: 'active',
      helpText:
        'Designates whether this user should be treated as active. Unselect this instead of deleting accounts.',
    }),
    dateJoined: new DateTimeField({ default: () => new Date(), verboseName: 'date joined' }),
  },
  { extends: PermissionsMixin },
) {
  static Meta = { abstract: true, verboseName: 'user', verboseNamePlural: 'users' }
  static override USERNAME_FIELD = 'username'
  static override EMAIL_FIELD = 'email'
  static override REQUIRED_FIELDS: string[] = ['email']

  override clean(): void | Promise<void> {
    super.clean()
    this.email = normalizeEmail(this.email)
  }

  /** First and last name with a space in between. */
  getFullName(): string {
    return `${this.firstName} ${this.lastName}`.trim()
  }

  getShortName(): string {
    return this.firstName
  }

  override toString(): string {
    return this.getUsername()
  }
}

/** The default user model (`auth.User`, table `auth_user`). Swap it with `AUTH_USER_MODEL`. */
export class User extends Model({}, { extends: AbstractUser }) {
  static Meta = { verboseName: 'user', verboseNamePlural: 'users', swappable: 'AUTH_USER_MODEL' }
  declare static objects: UserManager<User>
}

export { PERM_CACHE }
