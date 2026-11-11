// Django's django.core.signing, on WebCrypto. Byte-compatible with Django (same salts, separators, base64
// and zlib framing), so values signed by Ghuri and Django with the same SECRET_KEY verify on both sides.
import { GhuriError } from '@ghuri/core'
import {
  b62Decode,
  b62Encode,
  b64urlDecode,
  b64urlEncode,
  constantTimeCompare,
  fromUtf8,
  getSecretKey,
  getSecretKeyFallbacks,
  type HashAlgorithm,
  saltedHmac,
  utf8,
} from './utils/crypto'

/** Signature does not match. */
export class BadSignature extends GhuriError {}
/** Signature timestamp is older than `maxAge`. */
export class SignatureExpired extends BadSignature {}

export interface Serializer {
  dumps(obj: unknown): Uint8Array
  loads(data: Uint8Array): unknown
}

/** JSON with Python's `ensure_ascii` and compact separators (Django's `JSONSerializer`). */
export function asciiJson(obj: unknown): string {
  const s = JSON.stringify(obj)
  if (s === undefined) throw new TypeError('Value is not JSON serializable')
  return s.replace(/[\u0080-￿]/g, (ch) => `\\u${ch.charCodeAt(0).toString(16).padStart(4, '0')}`)
}

export const JSONSerializer: Serializer = {
  dumps: (obj) => utf8(asciiJson(obj)),
  loads: (data) => JSON.parse(fromUtf8(data)),
}

async function pipe(data: Uint8Array, stream: CompressionStream | DecompressionStream): Promise<Uint8Array> {
  const body = new Blob([data as Uint8Array<ArrayBuffer>]).stream().pipeThrough(stream)
  return new Uint8Array(await new Response(body).arrayBuffer())
}

/** zlib (RFC 1950) compression, like Python's `zlib.compress`. */
export function zlibCompress(data: Uint8Array): Promise<Uint8Array> {
  return pipe(data, new CompressionStream('deflate'))
}

export function zlibDecompress(data: Uint8Array): Promise<Uint8Array> {
  return pipe(data, new DecompressionStream('deflate'))
}

const SEP_UNSAFE = /^[A-Za-z0-9\-_=]*$/

export interface SignerOptions {
  /** Signing key (default `SECRET_KEY`). */
  key?: string
  /** Separator (default `':'`). */
  sep?: string
  /** Namespace for the signature (default `'django.core.signing.Signer'`, Django's default). */
  salt?: string
  algorithm?: HashAlgorithm
  /** Extra keys accepted when unsigning (default `SECRET_KEY_FALLBACKS`). */
  fallbackKeys?: string[]
}

export interface SignObjectOptions {
  serializer?: Serializer
  /** zlib-compress the payload when that makes it shorter. */
  compress?: boolean
}

/** Django's `Signer`: `value:signature` with an HMAC-SHA256 of `value`. All methods are async (WebCrypto). */
export class Signer {
  static defaultSalt = 'django.core.signing.Signer'
  readonly sep: string
  readonly salt: string
  readonly algorithm: HashAlgorithm
  private readonly _key?: string
  private readonly _fallbackKeys?: string[]

  constructor(opts: SignerOptions = {}) {
    this._key = opts.key
    this._fallbackKeys = opts.fallbackKeys
    this.sep = opts.sep ?? ':'
    this.salt = opts.salt ?? (this.constructor as typeof Signer).defaultSalt
    this.algorithm = opts.algorithm ?? 'sha256'
    if (SEP_UNSAFE.test(this.sep)) {
      throw new TypeError(
        `Unsafe Signer separator: '${this.sep}' (cannot be empty or consist of only A-z0-9-_=)`,
      )
    }
  }

  get key(): string {
    return this._key ?? getSecretKey()
  }

  get fallbackKeys(): string[] {
    return this._fallbackKeys ?? getSecretKeyFallbacks()
  }

  async signature(value: string, key?: string): Promise<string> {
    return b64urlEncode(await saltedHmac(`${this.salt}signer`, value, key ?? this.key, this.algorithm))
  }

  async sign(value: string): Promise<string> {
    return `${value}${this.sep}${await this.signature(value)}`
  }

  async unsign(signedValue: string): Promise<string> {
    const idx = signedValue.lastIndexOf(this.sep)
    if (idx < 0) throw new BadSignature(`No "${this.sep}" found in value`)
    const value = signedValue.slice(0, idx)
    const sig = signedValue.slice(idx + this.sep.length)
    for (const key of [this.key, ...this.fallbackKeys]) {
      if (constantTimeCompare(sig, await this.signature(value, key))) return value
    }
    throw new BadSignature(`Signature "${sig}" does not match`)
  }

  /** Serialize (JSON), optionally compress, base64 and sign an object (Django's `sign_object`). */
  async signObject(obj: unknown, opts: SignObjectOptions = {}): Promise<string> {
    let data = (opts.serializer ?? JSONSerializer).dumps(obj)
    let compressed = false
    if (opts.compress) {
      const z = await zlibCompress(data)
      if (z.length < data.length - 1) {
        data = z
        compressed = true
      }
    }
    let b64 = b64urlEncode(data)
    if (compressed) b64 = `.${b64}`
    return this.sign(b64)
  }

  async unsignObject(signedObj: string, opts: { serializer?: Serializer; maxAge?: number | null } = {}) {
    let b64 = await this.unsignWith(signedObj, opts.maxAge)
    const decompress = b64.startsWith('.')
    if (decompress) b64 = b64.slice(1)
    let data: Uint8Array
    try {
      data = b64urlDecode(b64)
      if (decompress) data = await zlibDecompress(data)
    } catch (err) {
      throw new BadSignature('Payload is not valid base64/zlib data', { cause: err })
    }
    return (opts.serializer ?? JSONSerializer).loads(data)
  }

  /** @internal unsign honoring maxAge for timestamp signers. */
  protected unsignWith(value: string, _maxAge?: number | null): Promise<string> {
    return this.unsign(value)
  }
}

/** Django's `TimestampSigner`: `value:timestamp:signature`; `unsign(value, maxAge)` checks the age. */
export class TimestampSigner extends Signer {
  static override defaultSalt = 'django.core.signing.TimestampSigner'

  timestamp(): string {
    return b62Encode(Math.floor(Date.now() / 1000))
  }

  override async sign(value: string): Promise<string> {
    return super.sign(`${value}${this.sep}${this.timestamp()}`)
  }

  /** `maxAge` in seconds. Throws `SignatureExpired` when older. */
  override async unsign(value: string, maxAge?: number | null): Promise<string> {
    const result = await super.unsign(value)
    const idx = result.lastIndexOf(this.sep)
    if (idx < 0) throw new BadSignature('Timestamp missing')
    const val = result.slice(0, idx)
    let ts: number
    try {
      ts = b62Decode(result.slice(idx + this.sep.length))
    } catch {
      throw new BadSignature('Invalid timestamp')
    }
    if (maxAge !== undefined && maxAge !== null) {
      const age = Date.now() / 1000 - ts
      if (age > maxAge) throw new SignatureExpired(`Signature age ${age} > ${maxAge} seconds`)
    }
    return val
  }

  protected override unsignWith(value: string, maxAge?: number | null): Promise<string> {
    return this.unsign(value, maxAge)
  }
}

export interface DumpsOptions {
  key?: string
  /** Default `'django.core.signing'` (Django's). */
  salt?: string
  serializer?: Serializer
  compress?: boolean
  fallbackKeys?: string[]
}

/**
 * Django's `signing.dumps()`: a URL-safe, signed, timestamped JSON string. Not encrypted — readable by
 * anyone, but tamper-proof.
 */
export function dumps(obj: unknown, opts: DumpsOptions = {}): Promise<string> {
  return new TimestampSigner({
    key: opts.key,
    salt: opts.salt ?? 'django.core.signing',
    fallbackKeys: opts.fallbackKeys,
  }).signObject(obj, {
    serializer: opts.serializer,
    compress: opts.compress,
  })
}

/** Django's `signing.loads()`. Throws `BadSignature` / `SignatureExpired` (`maxAge` in seconds). */
export function loads<T = any>(
  value: string,
  opts: Omit<DumpsOptions, 'compress'> & { maxAge?: number | null } = {},
): Promise<T> {
  return new TimestampSigner({
    key: opts.key,
    salt: opts.salt ?? 'django.core.signing',
    fallbackKeys: opts.fallbackKeys,
  }).unsignObject(value, { serializer: opts.serializer, maxAge: opts.maxAge }) as Promise<T>
}

/** `import { signing } from '@ghuri/auth'` — Django-style namespace. */
export const signing = {
  dumps,
  loads,
  Signer,
  TimestampSigner,
  BadSignature,
  SignatureExpired,
  JSONSerializer,
}
