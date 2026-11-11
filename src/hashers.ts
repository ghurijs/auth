// Password hashing (Django's django.contrib.auth.hashers) on WebCrypto. Hash strings use Django's formats:
//   pbkdf2_sha256$<iterations>$<salt>$<base64 hash>   pbkdf2_sha1$…   scrypt$<n>$<salt>$<r>$<p>$<base64 hash>
// so password hashes can move between Django and Ghuri in both directions.
import { ImproperlyConfigured, tryGetContext } from '@ghuri/core'
import { b64encode, constantTimeCompare, getRandomString, RANDOM_STRING_CHARS, utf8 } from './utils/crypto'
import { scrypt } from './utils/scrypt'
import { pbkdf2Js } from './utils/sha'

export const UNUSABLE_PASSWORD_PREFIX = '!'
export const UNUSABLE_PASSWORD_SUFFIX_LENGTH = 40

/**
 * Cloudflare's WebCrypto has rejected PBKDF2 above this iteration count (production Workers); Ghuri then
 * falls back to a pure-JS PBKDF2.
 */
export const WORKERS_PBKDF2_MAX_ITERATIONS = 100_000

/**
 * PBKDF2-HMAC. Uses WebCrypto, falling back to a pure-JS implementation when WebCrypto refuses the
 * parameters (Workers' iteration cap; empty passwords on some runtimes).
 */
export async function pbkdf2(
  password: string | Uint8Array,
  salt: string | Uint8Array,
  iterations: number,
  dkLen: number,
  digest: 'sha1' | 'sha256' = 'sha256',
): Promise<Uint8Array> {
  const pw = typeof password === 'string' ? utf8(password) : password
  const s = typeof salt === 'string' ? utf8(salt) : salt
  if (pw.length > 0) {
    try {
      const key = await crypto.subtle.importKey('raw', pw as Uint8Array<ArrayBuffer>, 'PBKDF2', false, [
        'deriveBits',
      ])
      const bits = await crypto.subtle.deriveBits(
        {
          name: 'PBKDF2',
          hash: digest === 'sha1' ? 'SHA-1' : 'SHA-256',
          salt: s as Uint8Array<ArrayBuffer>,
          iterations,
        },
        key,
        dkLen * 8,
      )
      return new Uint8Array(bits)
    } catch {
      // fall through to the JS implementation
    }
  }
  return pbkdf2Js(digest, pw, s, iterations, dkLen)
}

export interface DecodedHash {
  algorithm: string
  hash: string
  salt: string
  [key: string]: unknown
}

/** Base class for password hashers (Django's `BasePasswordHasher`). */
export abstract class BasePasswordHasher {
  abstract readonly algorithm: string
  /** Bits of entropy for generated salts. */
  saltEntropy = 128

  /** A new random salt. */
  salt(): string {
    const chars = Math.ceil(this.saltEntropy / Math.log2(RANDOM_STRING_CHARS.length))
    return getRandomString(chars, RANDOM_STRING_CHARS)
  }

  abstract encode(password: string, salt: string): Promise<string>
  abstract decode(encoded: string): DecodedHash

  async verify(password: string, encoded: string): Promise<boolean> {
    const decoded = this.decode(encoded)
    return constantTimeCompare(encoded, await this.encode(password, decoded.salt))
  }

  /** Summary with the salt and hash masked (admin display). */
  safeSummary(encoded: string): Record<string, string> {
    const d = this.decode(encoded)
    const out: Record<string, string> = {}
    for (const [k, v] of Object.entries(d)) {
      out[k] = k === 'hash' || k === 'salt' ? maskHash(String(v), k === 'hash' ? 6 : 4) : String(v)
    }
    return out
  }

  /** Should a hash be upgraded (different parameters)? */
  mustUpdate(_encoded: string): boolean {
    return false
  }

  /** Spend the time a verification with current parameters would take (timing attack mitigation). */
  async hardenRuntime(_password: string, _encoded: string): Promise<void> {}

  protected checkSalt(salt: string): void {
    if (!salt || salt.includes('$')) throw new TypeError('Salt must be non-empty and must not contain "$".')
  }

  protected mustUpdateSalt(salt: string, expectedEntropy: number): boolean {
    return salt.length * Math.log2(RANDOM_STRING_CHARS.length) < expectedEntropy
  }
}

/** First `show` characters, then asterisks (Django's `mask_hash`). */
export function maskHash(hash: string, show = 6, char = '*'): string {
  return hash.slice(0, show) + char.repeat(Math.max(0, hash.length - show))
}

export interface PBKDF2Options {
  iterations?: number
}

/**
 * PBKDF2-HMAC-SHA256, Django's default hasher, byte-compatible with Django's `pbkdf2_sha256`.
 *
 * Default 100,000 iterations: the most Cloudflare Workers' WebCrypto accepts and roughly 25–50 ms of CPU.
 * Django uses 1,000,000+ — such hashes still verify on Workers through a pure-JS PBKDF2 (~0.7 s of CPU,
 * needs the paid plan's CPU limit) and are re-hashed with the configured count on the next login.
 * Raise it on Node (`new PBKDF2PasswordHasher({ iterations: 600_000 })`), lower it if the free plan's
 * 10 ms CPU limit bites.
 */
export class PBKDF2PasswordHasher extends BasePasswordHasher {
  readonly algorithm: string = 'pbkdf2_sha256'
  iterations = 100_000
  readonly digest: 'sha1' | 'sha256' = 'sha256'

  constructor(opts: PBKDF2Options = {}) {
    super()
    if (opts.iterations !== undefined) this.iterations = opts.iterations
  }

  async encode(password: string, salt: string, iterations?: number): Promise<string> {
    this.checkSalt(salt)
    const iters = iterations ?? this.iterations
    const dkLen = this.digest === 'sha1' ? 20 : 32
    const hash = b64encode(await pbkdf2(password, salt, iters, dkLen, this.digest))
    return `${this.algorithm}$${iters}$${salt}$${hash}`
  }

  decode(encoded: string): DecodedHash {
    const parts = encoded.split('$')
    if (parts.length !== 4 || parts[0] !== this.algorithm) throw new TypeError('Invalid PBKDF2 hash')
    return { algorithm: parts[0], iterations: Number(parts[1]), salt: parts[2], hash: parts[3] }
  }

  override async verify(password: string, encoded: string): Promise<boolean> {
    const d = this.decode(encoded)
    return constantTimeCompare(encoded, await this.encode(password, d.salt, d.iterations as number))
  }

  override mustUpdate(encoded: string): boolean {
    const d = this.decode(encoded)
    return d.iterations !== this.iterations || this.mustUpdateSalt(d.salt, this.saltEntropy)
  }

  override async hardenRuntime(password: string, encoded: string): Promise<void> {
    const d = this.decode(encoded)
    const extra = this.iterations - (d.iterations as number)
    if (extra > 0) await this.encode(password, d.salt, extra)
  }
}

/** PBKDF2-HMAC-SHA1 (`pbkdf2_sha1$…`), for hashes from older Django setups. */
export class PBKDF2SHA1PasswordHasher extends PBKDF2PasswordHasher {
  override readonly algorithm: string = 'pbkdf2_sha1'
  override readonly digest: 'sha1' | 'sha256' = 'sha1'
}

export interface ScryptOptions {
  workFactor?: number
  blockSize?: number
  parallelism?: number
}

/**
 * scrypt (`scrypt$<n>$<salt>$<r>$<p>$<hash>`), compatible with Django's `ScryptPasswordHasher`.
 * WebCrypto has no scrypt: this runs a pure-JS scrypt (N=2^14, r=8 ≈ 16 MiB and ~90 ms of CPU on Node),
 * so it is mainly here to verify (and upgrade) hashes imported from Django.
 */
export class ScryptPasswordHasher extends BasePasswordHasher {
  readonly algorithm: string = 'scrypt'
  workFactor = 2 ** 14
  blockSize = 8
  parallelism = 1
  maxmem = 64 * 1024 * 1024

  constructor(opts: ScryptOptions = {}) {
    super()
    if (opts.workFactor) this.workFactor = opts.workFactor
    if (opts.blockSize) this.blockSize = opts.blockSize
    if (opts.parallelism) this.parallelism = opts.parallelism
  }

  async encode(password: string, salt: string, n?: number, r?: number, p?: number): Promise<string> {
    this.checkSalt(salt)
    const N = n ?? this.workFactor
    const R = r ?? this.blockSize
    const P = p ?? this.parallelism
    const hash = b64encode(
      scrypt(utf8(password), utf8(salt), { N, r: R, p: P, dkLen: 64, maxmem: this.maxmem }),
    )
    return `${this.algorithm}$${N}$${salt}$${R}$${P}$${hash}`
  }

  decode(encoded: string): DecodedHash {
    const parts = encoded.split('$')
    if (parts.length !== 6 || parts[0] !== this.algorithm) throw new TypeError('Invalid scrypt hash')
    return {
      algorithm: parts[0],
      workFactor: Number(parts[1]),
      salt: parts[2],
      blockSize: Number(parts[3]),
      parallelism: Number(parts[4]),
      hash: parts[5],
    }
  }

  override async verify(password: string, encoded: string): Promise<boolean> {
    const d = this.decode(encoded)
    const again = await this.encode(
      password,
      d.salt,
      d.workFactor as number,
      d.blockSize as number,
      d.parallelism as number,
    )
    return constantTimeCompare(encoded, again)
  }

  override mustUpdate(encoded: string): boolean {
    const d = this.decode(encoded)
    return (
      d.workFactor !== this.workFactor || d.blockSize !== this.blockSize || d.parallelism !== this.parallelism
    )
  }
}

// ---- registry ----------------------------------------------------------------------------------------

type HasherEntry = (new () => BasePasswordHasher) | BasePasswordHasher

export const DEFAULT_PASSWORD_HASHERS: HasherEntry[] = [
  PBKDF2PasswordHasher,
  PBKDF2SHA1PasswordHasher,
  ScryptPasswordHasher,
]

const cache = new WeakMap<object, BasePasswordHasher[]>()
let defaultInstances: BasePasswordHasher[] | undefined

function instantiate(list: HasherEntry[]): BasePasswordHasher[] {
  const out = list.map((h) => (typeof h === 'function' ? new h() : h))
  if (!out.length)
    throw new ImproperlyConfigured('You must specify at least one password hasher in PASSWORD_HASHERS.')
  for (const h of out) {
    if (!h || typeof h.encode !== 'function' || !h.algorithm) {
      throw new ImproperlyConfigured(`PASSWORD_HASHERS entry ${String(h)} is not a password hasher.`)
    }
  }
  return out
}

/** Configured hashers (`PASSWORD_HASHERS`), preferred first. */
export function getHashers(): BasePasswordHasher[] {
  const configured = tryGetContext()?.settings.PASSWORD_HASHERS as HasherEntry[] | undefined
  if (!configured) {
    defaultInstances ??= instantiate(DEFAULT_PASSWORD_HASHERS)
    return defaultInstances
  }
  let list = cache.get(configured)
  if (!list) {
    list = instantiate(configured)
    cache.set(configured, list)
  }
  return list
}

/** A hasher by algorithm name, or `'default'` for the preferred one. */
export function getHasher(algorithm: string | BasePasswordHasher = 'default'): BasePasswordHasher {
  if (typeof algorithm !== 'string') return algorithm
  const hashers = getHashers()
  if (algorithm === 'default') return hashers[0]
  const h = hashers.find((x) => x.algorithm === algorithm)
  if (!h) {
    throw new TypeError(
      `Unknown password hashing algorithm '${algorithm}'. Did you specify it in PASSWORD_HASHERS?`,
    )
  }
  return h
}

/** The hasher that produced `encoded` (throws TypeError for unknown formats). */
export function identifyHasher(encoded: string): BasePasswordHasher {
  if (!encoded?.includes('$')) throw new TypeError('Unknown password hashing algorithm.')
  return getHasher(encoded.split('$', 1)[0])
}

/** False for unusable passwords (`'!…'`). `null`/`undefined` count as usable, like Django. */
export function isPasswordUsable(encoded: string | null | undefined): boolean {
  return encoded === null || encoded === undefined || !encoded.startsWith(UNUSABLE_PASSWORD_PREFIX)
}

/** `'!'` + 40 random characters: never matches any password. */
export function makeUnusablePassword(): string {
  return UNUSABLE_PASSWORD_PREFIX + getRandomString(UNUSABLE_PASSWORD_SUFFIX_LENGTH)
}

/**
 * Hash a password for storage. `null` produces an unusable password. `hasher` is an algorithm name,
 * `'default'` (first of `PASSWORD_HASHERS`) or a hasher instance.
 */
export async function makePassword(
  password: string | null | undefined,
  salt?: string | null,
  hasher: string | BasePasswordHasher = 'default',
): Promise<string> {
  if (password === null || password === undefined) return makeUnusablePassword()
  if (typeof password !== 'string') throw new TypeError('Password must be a string.')
  const h = getHasher(hasher)
  return h.encode(password, salt ?? h.salt())
}

/** `[isCorrect, mustUpdate]` (Django's `verify_password`). */
export async function verifyPassword(
  password: string | null | undefined,
  encoded: string | null | undefined,
  preferred: string | BasePasswordHasher = 'default',
): Promise<[boolean, boolean]> {
  if (password === null || password === undefined || !encoded || !isPasswordUsable(encoded))
    return [false, false]
  const pref = getHasher(preferred)
  let hasher: BasePasswordHasher
  try {
    hasher = identifyHasher(encoded)
  } catch {
    return [false, false]
  }
  const changed = hasher.algorithm !== pref.algorithm
  let mustUpdate: boolean
  let ok: boolean
  try {
    mustUpdate = changed || pref.mustUpdate(encoded)
    ok = await hasher.verify(password, encoded)
  } catch {
    return [false, false]
  }
  if (!ok && !changed && mustUpdate) await hasher.hardenRuntime(password, encoded)
  return [ok, mustUpdate]
}

/**
 * Check a raw password against an encoded hash. When it matches but the hash uses outdated parameters
 * (another algorithm, iteration count), `setter(password)` is called so the caller can re-hash.
 */
export async function checkPassword(
  password: string | null | undefined,
  encoded: string | null | undefined,
  setter?: (password: string) => void | Promise<void>,
  preferred: string | BasePasswordHasher = 'default',
): Promise<boolean> {
  const [ok, mustUpdate] = await verifyPassword(password, encoded, preferred)
  if (setter && ok && mustUpdate) await setter(password as string)
  return ok
}
