// WebCrypto-only helpers (Workers-safe): randomness, encodings, HMAC, Django's salted_hmac.
import { ImproperlyConfigured, tryGetContext } from '@ghuri/core'

const encoder = new TextEncoder()
const decoder = new TextDecoder()

/** Django's `RANDOM_STRING_CHARS`. */
export const RANDOM_STRING_CHARS = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'

export function utf8(value: string): Uint8Array<ArrayBuffer> {
  return encoder.encode(value) as Uint8Array<ArrayBuffer>
}

export function fromUtf8(bytes: Uint8Array): string {
  return decoder.decode(bytes)
}

export function toBytes(value: string | Uint8Array): Uint8Array<ArrayBuffer> {
  return typeof value === 'string' ? utf8(value) : (new Uint8Array(value) as Uint8Array<ArrayBuffer>)
}

export function randomBytes(length: number): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(length)
  // getRandomValues is limited to 65536 bytes per call
  for (let i = 0; i < length; i += 65536) crypto.getRandomValues(out.subarray(i, Math.min(length, i + 65536)))
  return out
}

/** Django's `get_random_string()`: uniform choice from `allowed` (rejection sampling, no modulo bias). */
export function getRandomString(length: number, allowed: string = RANDOM_STRING_CHARS): string {
  const n = allowed.length
  if (n < 1 || n > 256) throw new RangeError('allowed must contain 1..256 characters')
  const limit = 256 - (256 % n)
  let out = ''
  while (out.length < length) {
    const bytes = randomBytes(Math.max(16, (length - out.length) * 2))
    for (const b of bytes) {
      if (b >= limit) continue
      out += allowed[b % n]
      if (out.length === length) break
    }
  }
  return out
}

export function bytesToHex(bytes: Uint8Array): string {
  let s = ''
  for (const b of bytes) s += b.toString(16).padStart(2, '0')
  return s
}

export function hexToBytes(hex: string): Uint8Array<ArrayBuffer> {
  if (hex.length % 2 || /[^0-9a-f]/i.test(hex)) throw new TypeError('Invalid hex string')
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return out
}

function bytesToBinary(bytes: Uint8Array): string {
  let s = ''
  for (let i = 0; i < bytes.length; i += 0x8000) {
    s += String.fromCharCode(...bytes.subarray(i, i + 0x8000))
  }
  return s
}

/** Standard base64 with padding (Python's `base64.b64encode`). */
export function b64encode(bytes: Uint8Array): string {
  return btoa(bytesToBinary(bytes))
}

export function b64decode(value: string): Uint8Array<ArrayBuffer> {
  const bin = atob(value)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

/** URL-safe base64 without padding (Django's `signing.b64_encode` / `urlsafe_base64_encode`). */
export function b64urlEncode(bytes: Uint8Array): string {
  return b64encode(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

/** Decode URL-safe base64, with or without padding. Throws on invalid input. */
export function b64urlDecode(value: string): Uint8Array<ArrayBuffer> {
  if (/[^A-Za-z0-9_\-=]/.test(value)) throw new TypeError('Invalid base64 string')
  const std = value.replace(/-/g, '+').replace(/_/g, '/').replace(/=+$/, '')
  return b64decode(std + '='.repeat((4 - (std.length % 4)) % 4))
}

/** Constant-time comparison of two strings or byte arrays. */
export function constantTimeCompare(a: string | Uint8Array, b: string | Uint8Array): boolean {
  const x = toBytes(a)
  const y = toBytes(b)
  // Like hmac.compare_digest, only the length may leak.
  let diff = x.length ^ y.length
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ (y[i] ?? 0)
  return diff === 0
}

export type HashAlgorithm = 'sha1' | 'sha256' | 'sha384' | 'sha512'

export function webCryptoHash(algorithm: HashAlgorithm): string {
  switch (algorithm) {
    case 'sha1':
      return 'SHA-1'
    case 'sha256':
      return 'SHA-256'
    case 'sha384':
      return 'SHA-384'
    case 'sha512':
      return 'SHA-512'
    default:
      throw new TypeError(`Unsupported hash algorithm '${String(algorithm)}'`)
  }
}

export async function digest(algorithm: HashAlgorithm, data: string | Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest(webCryptoHash(algorithm), toBytes(data)))
}

export async function hmac(
  algorithm: HashAlgorithm,
  key: string | Uint8Array,
  message: string | Uint8Array,
): Promise<Uint8Array> {
  const k = await crypto.subtle.importKey(
    'raw',
    toBytes(key),
    { name: 'HMAC', hash: webCryptoHash(algorithm) },
    false,
    ['sign'],
  )
  return new Uint8Array(await crypto.subtle.sign('HMAC', k, toBytes(message)))
}

/** The project's `SECRET_KEY` (from the current Ghuri context). */
export function getSecretKey(): string {
  const key = tryGetContext()?.settings.SECRET_KEY
  if (!key) throw new ImproperlyConfigured('The SECRET_KEY setting must not be empty.')
  return key
}

/** `SECRET_KEY_FALLBACKS` (old keys still accepted when verifying signatures). */
export function getSecretKeyFallbacks(): string[] {
  return (tryGetContext()?.settings.SECRET_KEY_FALLBACKS as string[] | undefined) ?? []
}

/**
 * Django's `salted_hmac(key_salt, value, secret, algorithm)`: HMAC of `value` with a key derived from
 * `key_salt + secret` (byte-compatible with Django).
 */
export async function saltedHmac(
  keySalt: string,
  value: string | Uint8Array,
  secret?: string,
  algorithm: HashAlgorithm = 'sha1',
): Promise<Uint8Array> {
  const key = await digest(algorithm, keySalt + (secret ?? getSecretKey()))
  return hmac(algorithm, key, value)
}

// ---- integer encodings ---------------------------------------------------------------------------

const B62 = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'

/** Django's `signing.b62_encode`. */
export function b62Encode(n: number): string {
  if (n === 0) return '0'
  const sign = n < 0 ? '-' : ''
  let v = Math.abs(Math.trunc(n))
  let out = ''
  while (v > 0) {
    out = B62[v % 62] + out
    v = Math.floor(v / 62)
  }
  return sign + out
}

export function b62Decode(s: string): number {
  if (s === '0') return 0
  let sign = 1
  let str = s
  if (str.startsWith('-')) {
    sign = -1
    str = str.slice(1)
  }
  let n = 0
  for (const ch of str) {
    const i = B62.indexOf(ch)
    if (i < 0) throw new TypeError(`Invalid base62 value '${s}'`)
    n = n * 62 + i
  }
  return sign * n
}

/** Django's `int_to_base36`. */
export function intToBase36(n: number): string {
  if (n < 0) throw new RangeError('Negative base36 conversion input.')
  return Math.trunc(n).toString(36)
}

/** Django's `base36_to_int` (max 13 chars). */
export function base36ToInt(s: string): number {
  if (s.length > 13 || !/^[0-9a-z]+$/i.test(s)) throw new TypeError('Base36 input too large or invalid')
  return Number.parseInt(s, 36)
}

/** Django's `urlsafe_base64_encode(force_bytes(value))`. */
export function urlsafeBase64Encode(value: string | number | Uint8Array): string {
  return b64urlEncode(typeof value === 'number' ? utf8(String(value)) : toBytes(value))
}

/** Django's `urlsafe_base64_decode(...)` decoded as UTF-8. */
export function urlsafeBase64Decode(value: string): string {
  return fromUtf8(b64urlDecode(value))
}
