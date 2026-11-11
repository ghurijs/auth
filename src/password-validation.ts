// Django's django.contrib.auth.password_validation.
import { ImproperlyConfigured, tryGetContext, ValidationError } from '@ghuri/core'
import { COMMON_PASSWORDS } from './common-passwords'

export interface PasswordValidator {
  /** Throw `ValidationError` when the password is not acceptable. */
  validate(password: string, user?: any): void | Promise<void>
  getHelpText?(): string
  /** Called after a user's password changed (e.g. to record password history). */
  passwordChanged?(password: string, user?: any): void | Promise<void>
}

export type PasswordValidatorClass = new (options?: any) => PasswordValidator

/**
 * `AUTH_PASSWORD_VALIDATORS` entry: Django's `{ NAME, OPTIONS }` dict (NAME is the class), a class, or an
 * instance.
 */
export type PasswordValidatorConfig =
  | { NAME: PasswordValidatorClass; OPTIONS?: Record<string, unknown> }
  | PasswordValidatorClass
  | PasswordValidator

/** At least `minLength` characters (default 8). */
export class MinimumLengthValidator implements PasswordValidator {
  readonly minLength: number
  constructor(opts: { minLength?: number; min_length?: number } = {}) {
    this.minLength = opts.minLength ?? opts.min_length ?? 8
  }
  validate(password: string): void {
    if (password.length < this.minLength) {
      throw new ValidationError(
        `This password is too short. It must contain at least ${this.minLength} character${this.minLength === 1 ? '' : 's'}.`,
        { code: 'password_too_short' },
      )
    }
  }
  getHelpText(): string {
    return `Your password must contain at least ${this.minLength} character${this.minLength === 1 ? '' : 's'}.`
  }
}

/** Django's `exceeds_maximum_length_ratio`. */
function exceedsMaximumLengthRatio(password: string, maxSimilarity: number, value: string): boolean {
  const pwdLen = password.length
  const lengthBoundSimilarity = (maxSimilarity / 2) * pwdLen
  const valueLen = value.length
  return pwdLen >= 10 * valueLen && valueLen < lengthBoundSimilarity
}

/** difflib's `SequenceMatcher(a, b).quick_ratio()` (multiset intersection). */
export function quickRatio(a: string, b: string): number {
  const total = a.length + b.length
  if (!total) return 1
  const counts = new Map<string, number>()
  for (const ch of b) counts.set(ch, (counts.get(ch) ?? 0) + 1)
  let matches = 0
  for (const ch of a) {
    const n = counts.get(ch) ?? 0
    if (n > 0) {
      matches++
      counts.set(ch, n - 1)
    }
  }
  return (2 * matches) / total
}

/** Rejects passwords too similar to the user's attributes (username, names, email). */
export class UserAttributeSimilarityValidator implements PasswordValidator {
  static DEFAULT_USER_ATTRIBUTES = ['username', 'firstName', 'lastName', 'email']
  readonly userAttributes: string[]
  readonly maxSimilarity: number

  constructor(opts: { userAttributes?: string[]; maxSimilarity?: number } = {}) {
    this.userAttributes = opts.userAttributes ?? UserAttributeSimilarityValidator.DEFAULT_USER_ATTRIBUTES
    this.maxSimilarity = opts.maxSimilarity ?? 0.7
    if (this.maxSimilarity < 0.1) throw new RangeError('maxSimilarity must be at least 0.1')
  }

  validate(password: string, user?: any): void {
    if (!user) return
    const pw = password.toLowerCase()
    for (const attr of this.userAttributes) {
      const value = user[attr]
      if (!value || typeof value !== 'string') continue
      const lower = value.toLowerCase()
      const parts = [...lower.split(/[^\p{L}\p{N}_]+/u), lower]
      for (const part of parts) {
        if (exceedsMaximumLengthRatio(pw, this.maxSimilarity, part)) continue
        if (quickRatio(pw, part) >= this.maxSimilarity) {
          let verbose = attr
          try {
            verbose = (user.constructor?._meta?.getField?.(attr)?.verboseName as string | undefined) ?? attr
          } catch {}
          throw new ValidationError(`The password is too similar to the ${verbose}.`, {
            code: 'password_too_similar',
          })
        }
      }
    }
  }

  getHelpText(): string {
    return 'Your password can’t be too similar to your other personal information.'
  }
}

/** Rejects common passwords (a compact built-in list, or your own `passwords`). */
export class CommonPasswordValidator implements PasswordValidator {
  readonly passwords: ReadonlySet<string>
  constructor(opts: { passwords?: Iterable<string> } = {}) {
    this.passwords = opts.passwords
      ? new Set([...opts.passwords].map((p) => p.trim().toLowerCase()))
      : COMMON_PASSWORDS
  }
  validate(password: string): void {
    if (this.passwords.has(password.toLowerCase().trim())) {
      throw new ValidationError('This password is too common.', { code: 'password_too_common' })
    }
  }
  getHelpText(): string {
    return 'Your password can’t be a commonly used password.'
  }
}

/** Rejects entirely numeric passwords. */
export class NumericPasswordValidator implements PasswordValidator {
  validate(password: string): void {
    if (/^\p{Nd}+$/u.test(password)) {
      throw new ValidationError('This password is entirely numeric.', { code: 'password_entirely_numeric' })
    }
  }
  getHelpText(): string {
    return 'Your password can’t be entirely numeric.'
  }
}

function build(config: PasswordValidatorConfig): PasswordValidator {
  if (typeof config === 'function') return new config()
  if (config && typeof (config as PasswordValidator).validate === 'function')
    return config as PasswordValidator
  const entry = config as { NAME: PasswordValidatorClass; OPTIONS?: Record<string, unknown> }
  if (typeof entry?.NAME !== 'function') {
    throw new ImproperlyConfigured(`Invalid AUTH_PASSWORD_VALIDATORS entry: ${JSON.stringify(config)}`)
  }
  return new entry.NAME(entry.OPTIONS ?? {})
}

const cache = new WeakMap<object, PasswordValidator[]>()

/** Instantiate validators from a config list. */
export function getPasswordValidators(configs: PasswordValidatorConfig[]): PasswordValidator[] {
  let list = cache.get(configs)
  if (!list) {
    list = configs.map(build)
    cache.set(configs, list)
  }
  return list
}

/** Validators from `AUTH_PASSWORD_VALIDATORS` (none by default, like Django). */
export function getDefaultPasswordValidators(): PasswordValidator[] {
  const configs = tryGetContext()?.settings.AUTH_PASSWORD_VALIDATORS as PasswordValidatorConfig[] | undefined
  return configs ? getPasswordValidators(configs) : []
}

/**
 * Validate a password against every validator; throws one `ValidationError` with all messages.
 * `user` (optional, may be unsaved) is used by the similarity validator.
 */
export async function validatePassword(
  password: string,
  user?: any,
  validators: PasswordValidator[] = getDefaultPasswordValidators(),
): Promise<void> {
  const errors: string[] = []
  for (const v of validators) {
    try {
      await v.validate(password, user)
    } catch (err) {
      if (err instanceof ValidationError) errors.push(...err.messages)
      else throw err
    }
  }
  if (errors.length) throw new ValidationError(errors, { code: 'password_invalid' })
}

/** Inform validators that a password changed (Django's `password_changed`). */
export async function passwordChanged(
  password: string,
  user?: any,
  validators: PasswordValidator[] = getDefaultPasswordValidators(),
): Promise<void> {
  for (const v of validators) await v.passwordChanged?.(password, user)
}

export function passwordValidatorsHelpTexts(
  validators: PasswordValidator[] = getDefaultPasswordValidators(),
): string[] {
  return validators.map((v) => v.getHelpText?.() ?? '').filter(Boolean)
}
