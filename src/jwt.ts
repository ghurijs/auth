// JSON Web Tokens (djangorestframework-simplejwt style) on `hono/jwt` (WebCrypto).
import { apps, tryGetContext } from '@ghuri/core'
import type { ModelClass } from '@ghuri/orm'
import { decode as jwtDecode, sign as jwtSign, verify as jwtVerify } from 'hono/jwt'
import { TokenError } from './errors'
import type { AbstractBaseUser } from './models/auth'
import { BlacklistedToken, OutstandingToken } from './models/tokens'
import { getUserModel } from './user-model'
import { bytesToHex, digest, getRandomString, getSecretKey } from './utils/crypto'

export type JWTAlgorithm =
  | 'HS256'
  | 'HS384'
  | 'HS512'
  | 'RS256'
  | 'RS384'
  | 'RS512'
  | 'PS256'
  | 'PS384'
  | 'PS512'
  | 'ES256'
  | 'ES384'
  | 'ES512'
  | 'EdDSA'

/** `JWT` setting (simplejwt names; lifetimes in seconds). */
export interface JWTSettings {
  /** Seconds (default 300). */
  ACCESS_TOKEN_LIFETIME?: number
  /** Seconds (default 86400). */
  REFRESH_TOKEN_LIFETIME?: number
  /** Issue a new refresh token on refresh (default false). */
  ROTATE_REFRESH_TOKENS?: boolean
  /** Blacklist the old refresh token when rotating (needs the `token_blacklist` app; default false). */
  BLACKLIST_AFTER_ROTATION?: boolean
  /** Update `lastLogin` when obtaining a token pair (default false). */
  UPDATE_LAST_LOGIN?: boolean
  ALGORITHM?: JWTAlgorithm
  /** Default `SECRET_KEY`. For RS/ES/PS/EdDSA: a PEM private key. */
  SIGNING_KEY?: string
  /** Public key for asymmetric algorithms (default `SIGNING_KEY`). */
  VERIFYING_KEY?: string
  AUDIENCE?: string
  ISSUER?: string
  /** Allowed clock skew in seconds (default 0). */
  LEEWAY?: number
  /** Accepted `Authorization` schemes (default `['Bearer']`). */
  AUTH_HEADER_TYPES?: string[]
  /** User field identifying the user (default `'id'`). */
  USER_ID_FIELD?: string
  /** Claim holding it (default `'user_id'`). */
  USER_ID_CLAIM?: string
  TOKEN_TYPE_CLAIM?: string
  JTI_CLAIM?: string
  /** Reject access tokens issued before the user's last password change (default false). */
  CHECK_REVOKE_TOKEN?: boolean
  REVOKE_TOKEN_CLAIM?: string
}

export interface ResolvedJWTSettings {
  ACCESS_TOKEN_LIFETIME: number
  REFRESH_TOKEN_LIFETIME: number
  ROTATE_REFRESH_TOKENS: boolean
  BLACKLIST_AFTER_ROTATION: boolean
  UPDATE_LAST_LOGIN: boolean
  ALGORITHM: JWTAlgorithm
  SIGNING_KEY: string
  VERIFYING_KEY: string
  AUDIENCE?: string
  ISSUER?: string
  LEEWAY: number
  AUTH_HEADER_TYPES: string[]
  USER_ID_FIELD: string
  USER_ID_CLAIM: string
  TOKEN_TYPE_CLAIM: string
  JTI_CLAIM: string
  CHECK_REVOKE_TOKEN: boolean
  REVOKE_TOKEN_CLAIM: string
}

/** JWT settings with defaults applied. */
export function jwtSettings(): ResolvedJWTSettings {
  const s = tryGetContext()?.settings
  const user = ((s?.JWT ?? s?.SIMPLE_JWT) as JWTSettings | undefined) ?? {}
  const signingKey = user.SIGNING_KEY ?? getSecretKey()
  return {
    ACCESS_TOKEN_LIFETIME: user.ACCESS_TOKEN_LIFETIME ?? 5 * 60,
    REFRESH_TOKEN_LIFETIME: user.REFRESH_TOKEN_LIFETIME ?? 24 * 60 * 60,
    ROTATE_REFRESH_TOKENS: user.ROTATE_REFRESH_TOKENS ?? false,
    BLACKLIST_AFTER_ROTATION: user.BLACKLIST_AFTER_ROTATION ?? false,
    UPDATE_LAST_LOGIN: user.UPDATE_LAST_LOGIN ?? false,
    ALGORITHM: user.ALGORITHM ?? 'HS256',
    SIGNING_KEY: signingKey,
    VERIFYING_KEY: user.VERIFYING_KEY ?? signingKey,
    AUDIENCE: user.AUDIENCE,
    ISSUER: user.ISSUER,
    LEEWAY: user.LEEWAY ?? 0,
    AUTH_HEADER_TYPES: user.AUTH_HEADER_TYPES ?? ['Bearer'],
    USER_ID_FIELD: user.USER_ID_FIELD ?? 'id',
    USER_ID_CLAIM: user.USER_ID_CLAIM ?? 'user_id',
    TOKEN_TYPE_CLAIM: user.TOKEN_TYPE_CLAIM ?? 'token_type',
    JTI_CLAIM: user.JTI_CLAIM ?? 'jti',
    CHECK_REVOKE_TOKEN: user.CHECK_REVOKE_TOKEN ?? false,
    REVOKE_TOKEN_CLAIM: user.REVOKE_TOKEN_CLAIM ?? 'hash_password',
  }
}

const nowSeconds = () => Math.floor(Date.now() / 1000)

/** Is the `token_blacklist` app installed? */
export function blacklistInstalled(): boolean {
  try {
    return apps.isInstalled('token_blacklist')
  } catch {
    return false
  }
}

/** Hash of the password hash, for `CHECK_REVOKE_TOKEN` (simplejwt uses MD5, unavailable in WebCrypto). */
export async function passwordRevokeHash(password: string): Promise<string> {
  return bytesToHex(await digest('sha256', password)).slice(0, 32)
}

export type JWTPayload = Record<string, any>

/**
 * Base JWT (simplejwt's `Token`). Build one with `await RefreshToken.forUser(user)`, read claims with
 * `token.payload`, serialize with `await token.encode()`, parse with `await AccessToken.fromString(str)`.
 */
export class JWTToken {
  /** `token_type` claim value (`null` = any). */
  static tokenType: string | null = null
  /** Lifetime in seconds (from settings in subclasses). */
  static lifetime(): number {
    return jwtSettings().ACCESS_TOKEN_LIFETIME
  }

  /**
   * The model whose key the `USER_ID_CLAIM` holds (default `AUTH_USER_MODEL`). Override in a token subclass with its
   * own `tokenType` to issue tokens for another model, e.g. a shop's customers:
   *
   * ```ts
   * class CustomerAccessToken extends AccessToken {
   *   static override tokenType = 'customer_access'
   *   static override userModel() { return Customer }
   * }
   * ```
   */
  static userModel(): ModelClass {
    return getUserModel() as unknown as ModelClass
  }

  payload: JWTPayload
  /** The encoded token this instance was parsed from. */
  token?: string
  /** Creation time (seconds). */
  readonly currentTime: number

  constructor(payload: JWTPayload = {}, opts: { fresh?: boolean } = {}) {
    this.currentTime = nowSeconds()
    this.payload = { ...payload }
    if (opts.fresh !== false && !Object.keys(payload).length) {
      const cls = this.constructor as typeof JWTToken
      const s = jwtSettings()
      if (cls.tokenType) this.payload[s.TOKEN_TYPE_CLAIM] = cls.tokenType
      this.setExp()
      this.setIat()
      this.setJti()
    }
  }

  get(claim: string): any {
    return this.payload[claim]
  }

  set(claim: string, value: unknown): void {
    this.payload[claim] = value
  }

  setJti(): void {
    this.payload[jwtSettings().JTI_CLAIM] = getRandomString(32, 'abcdef0123456789')
  }

  setExp(opts: { fromTime?: number; lifetime?: number } = {}): void {
    const from = opts.fromTime ?? this.currentTime
    this.payload.exp = from + (opts.lifetime ?? (this.constructor as typeof JWTToken).lifetime())
  }

  setIat(at?: number): void {
    this.payload.iat = at ?? this.currentTime
  }

  /** Throws `TokenError` if `exp` (or `claim`) is in the past. */
  checkExp(claim = 'exp', currentTime = nowSeconds()): void {
    const v = this.payload[claim]
    if (v === undefined) throw new TokenError(`Token has no '${claim}' claim`)
    if (Number(v) + jwtSettings().LEEWAY <= currentTime)
      throw new TokenError(`Token '${claim}' claim has expired`)
  }

  /** Signed compact JWT. */
  async encode(): Promise<string> {
    const s = jwtSettings()
    const payload = { ...this.payload }
    if (s.AUDIENCE !== undefined) payload.aud = s.AUDIENCE
    if (s.ISSUER !== undefined) payload.iss = s.ISSUER
    return jwtSign(payload, s.SIGNING_KEY, s.ALGORITHM)
  }

  /** Verify signature, expiry and token type. */
  static async fromString<T extends JWTToken>(
    this: new (
      p?: JWTPayload,
      o?: { fresh?: boolean },
    ) => T,
    token: string,
    opts: { verify?: boolean } = {},
  ): Promise<T> {
    const s = jwtSettings()
    let payload: JWTPayload
    try {
      if (opts.verify === false) {
        payload = jwtDecode(token).payload as JWTPayload
      } else {
        payload = (await jwtVerify(token, s.VERIFYING_KEY, {
          alg: s.ALGORITHM,
          exp: false,
          nbf: true,
          iat: false,
          ...(s.ISSUER !== undefined ? { iss: s.ISSUER } : {}),
          ...(s.AUDIENCE !== undefined ? { aud: s.AUDIENCE } : {}),
        })) as JWTPayload
      }
    } catch (err) {
      throw new TokenError('Token is invalid', { cause: err })
    }
    const t = new this(payload, { fresh: false })
    t.token = token
    if (opts.verify !== false) await t.verify()
    return t
  }

  /** Checks run after the signature verified. */
  async verify(): Promise<void> {
    this.checkExp()
    const s = jwtSettings()
    if (s.JTI_CLAIM && this.payload[s.JTI_CLAIM] === undefined) throw new TokenError('Token has no id')
    this.verifyTokenType()
  }

  verifyTokenType(): void {
    const expected = (this.constructor as typeof JWTToken).tokenType
    if (expected === null) return
    const s = jwtSettings()
    if (this.payload[s.TOKEN_TYPE_CLAIM] !== expected) throw new TokenError('Token has wrong type')
  }

  /** New token of this type for `user` (adds the user-id claim). */
  static async forUser<T extends JWTToken>(
    this: new (
      p?: JWTPayload,
    ) => T,
    user: AbstractBaseUser,
  ): Promise<T> {
    const s = jwtSettings()
    let userId = (user as any)[s.USER_ID_FIELD]
    if (typeof userId === 'bigint' || (typeof userId !== 'string' && typeof userId !== 'number'))
      userId = String(userId)
    const t = new this()
    t.payload[s.USER_ID_CLAIM] = userId
    if (s.CHECK_REVOKE_TOKEN) t.payload[s.REVOKE_TOKEN_CLAIM] = await passwordRevokeHash(user.password)
    return t
  }
}

/** Short-lived token sent as `Authorization: Bearer <access>`. */
export class AccessToken extends JWTToken {
  static override tokenType: string | null = 'access'
  static override lifetime(): number {
    return jwtSettings().ACCESS_TOKEN_LIFETIME
  }
}

/** Accepts any token type (verification endpoints). */
export class UntypedToken extends JWTToken {
  static override tokenType: string | null = null
  override verifyTokenType(): void {}
}

const NO_COPY_CLAIMS = () => {
  const s = jwtSettings()
  return new Set([s.TOKEN_TYPE_CLAIM, 'exp', s.JTI_CLAIM, 'jti', 'iat'])
}

/**
 * Long-lived token exchanged for access tokens. With the `token_blacklist` app installed, refresh tokens
 * are recorded (`OutstandingToken`) and can be revoked (`await refresh.blacklist()`).
 */
export class RefreshToken extends JWTToken {
  static override tokenType: string | null = 'refresh'
  static override lifetime(): number {
    return jwtSettings().REFRESH_TOKEN_LIFETIME
  }

  /** Access token class `accessToken` returns (override with a custom refresh token class). */
  static accessTokenClass: typeof AccessToken = AccessToken

  /** A new access token carrying this refresh token's custom claims. */
  get accessToken(): AccessToken {
    const access = new (this.constructor as typeof RefreshToken).accessTokenClass()
    access.setExp({ fromTime: this.currentTime })
    const skip = NO_COPY_CLAIMS()
    for (const [k, v] of Object.entries(this.payload)) if (!skip.has(k)) access.payload[k] = v
    return access
  }

  override async verify(): Promise<void> {
    await super.verify()
    await this.checkBlacklist()
  }

  /** Throws `TokenError` if this token was blacklisted. */
  async checkBlacklist(): Promise<void> {
    if (!blacklistInstalled()) return
    const jti = this.payload[jwtSettings().JTI_CLAIM]
    if (await BlacklistedToken.objects.filter({ token__jti: jti }).exists()) {
      throw new TokenError('Token is blacklisted')
    }
  }

  /** Record this token as outstanding (no-op without the `token_blacklist` app). */
  async outstand(): Promise<OutstandingToken | null> {
    if (!blacklistInstalled()) return null
    const s = jwtSettings()
    const jti = this.payload[s.JTI_CLAIM]
    const existing = await OutstandingToken.objects.filter({ jti }).first()
    if (existing) return existing
    const userId = this.payload[s.USER_ID_CLAIM]
    let user: unknown = null
    // OutstandingToken.user points to AUTH_USER_MODEL: tokens of another model are recorded without a user.
    const model = (this.constructor as typeof JWTToken).userModel()
    if (userId !== undefined && userId !== null && model === (getUserModel() as unknown)) {
      user = await model._defaultManager.filter({ [s.USER_ID_FIELD]: userId }).first()
    }
    return OutstandingToken.objects.create({
      user: user as any,
      jti,
      token: await this.encode(),
      createdAt: new Date(this.payload.iat ? this.payload.iat * 1000 : Date.now()),
      expiresAt: new Date(this.payload.exp * 1000),
    })
  }

  /** Blacklist this token (requires the `token_blacklist` app). */
  async blacklist(): Promise<BlacklistedToken> {
    if (!blacklistInstalled())
      throw new TokenError("The 'token_blacklist' app (TokenBlacklistConfig) is not installed")
    const outstanding = await this.outstand()
    const [b] = await BlacklistedToken.objects.getOrCreate({ token: outstanding as any })
    return b
  }

  static override async forUser<T extends JWTToken>(
    this: new (
      p?: JWTPayload,
    ) => T,
    user: AbstractBaseUser,
  ): Promise<T> {
    const t = (await JWTToken.forUser.call(this as any, user)) as unknown as RefreshToken
    await t.outstand()
    return t as unknown as T
  }
}

/** `{ refresh, access }` for a user (what `TokenObtainPairView` returns). */
export async function tokenPairForUser(user: AbstractBaseUser): Promise<{ refresh: string; access: string }> {
  const refresh = await RefreshToken.forUser(user)
  return { refresh: await refresh.encode(), access: await refresh.accessToken.encode() }
}
