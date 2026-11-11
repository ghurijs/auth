// @ghuri/auth/rest — DRF-style authentication classes and token views. Structural: no import of @ghuri/rest.
// REST contract: `new Cls()` then `authenticate(c): Promise<[RequestUser, unknown] | null>` and
// `authenticateHeader?(c): string | undefined`.
import { enforceCsrf, getUser, json, type RequestUser, setUser, ValidationError, View } from '@ghuri/core'
import type { Context } from 'hono'
import { authenticate, getUserFromSession } from './auth'
import { AuthenticationFailed, InvalidToken, TokenError } from './errors'
import {
  AccessToken,
  type JWTToken,
  jwtSettings,
  passwordRevokeHash,
  RefreshToken,
  UntypedToken,
} from './jwt'
import type { AbstractBaseUser } from './models/auth'
import { Token } from './models/tokens'
import { getUserModel } from './user-model'
import { b64decode, fromUtf8 } from './utils/crypto'
import { readData } from './views'

export type AuthResult = [RequestUser, unknown] | null

/** What `@ghuri/rest` expects from an authentication class. */
export interface BaseAuthentication {
  authenticate(c: Context): Promise<AuthResult>
  authenticateHeader?(c: Context): string | undefined
}

/** The `Authorization` header split on whitespace. */
function authorizationParts(c: Context): string[] {
  const h = c.req.header('authorization')
  return h ? h.trim().split(/\s+/) : []
}

/**
 * Uses the Django session (`SessionMiddleware` + `AuthenticationMiddleware`) and enforces CSRF on unsafe
 * methods (DRF's `SessionAuthentication`). Returns null for anonymous / inactive users.
 */
export class SessionAuthentication implements BaseAuthentication {
  async authenticate(c: Context): Promise<AuthResult> {
    let user = c.get('user') as RequestUser | undefined
    if (!user && c.get('session')) {
      user = await getUserFromSession(c)
      setUser(c, user)
    }
    user ??= getUser(c)
    if (!user?.isAuthenticated || user.isActive === false) return null
    await this.enforceCsrf(c)
    return [user, null]
  }

  /** Throws `CsrfFailure` (403) for unsafe requests without a valid CSRF token. */
  async enforceCsrf(c: Context): Promise<void> {
    await enforceCsrf(c)
  }
}

/** `Authorization: Token <key>` against the `authtoken.Token` model (DRF's `TokenAuthentication`). */
export class TokenAuthentication implements BaseAuthentication {
  keyword = 'Token'
  /** Token model (override for custom token models). */
  model: { objects: any; DoesNotExist: new (...a: any[]) => Error } = Token

  async authenticate(c: Context): Promise<AuthResult> {
    const auth = authorizationParts(c)
    if (!auth.length || auth[0].toLowerCase() !== this.keyword.toLowerCase()) return null
    if (auth.length === 1) throw this.fail('Invalid token header. No credentials provided.')
    if (auth.length > 2) throw this.fail('Invalid token header. Token string should not contain spaces.')
    return this.authenticateCredentials(auth[1])
  }

  async authenticateCredentials(key: string): Promise<AuthResult> {
    let token: any
    try {
      token = await this.model.objects.selectRelated('user').get({ key })
    } catch (err) {
      if (err instanceof this.model.DoesNotExist) throw this.fail('Invalid token.')
      throw err
    }
    const user = await token.user
    if (!user || user.isActive === false) throw this.fail('User inactive or deleted.')
    return [user, token]
  }

  authenticateHeader(_c?: Context): string {
    return this.keyword
  }

  protected fail(detail: string): AuthenticationFailed {
    const err = new AuthenticationFailed(detail)
    err.authenticateHeader = this.authenticateHeader()
    return err
  }
}

/** `Authorization: Basic base64(user:pass)` (DRF's `BasicAuthentication`). */
export class BasicAuthentication implements BaseAuthentication {
  wwwAuthenticateRealm = 'api'

  async authenticate(c: Context): Promise<AuthResult> {
    const auth = authorizationParts(c)
    if (!auth.length || auth[0].toLowerCase() !== 'basic') return null
    if (auth.length === 1) throw this.fail('Invalid basic header. No credentials provided.')
    if (auth.length > 2)
      throw this.fail('Invalid basic header. Credentials string should not contain spaces.')
    let decoded: string
    try {
      decoded = fromUtf8(b64decode(auth[1]))
    } catch {
      throw this.fail('Invalid basic header. Credentials not correctly base64 encoded.')
    }
    const idx = decoded.indexOf(':')
    if (idx < 0) throw this.fail('Invalid basic header. Credentials not correctly base64 encoded.')
    return this.authenticateCredentials(decoded.slice(0, idx), decoded.slice(idx + 1), c)
  }

  async authenticateCredentials(userid: string, password: string, c?: Context): Promise<AuthResult> {
    const User = getUserModel()
    const user = await authenticate(c, { [User.USERNAME_FIELD]: userid, password })
    if (!user) throw this.fail('Invalid username/password.')
    if ((user as any).isActive === false) throw this.fail('User inactive or deleted.')
    return [user as unknown as RequestUser, null]
  }

  authenticateHeader(_c?: Context): string {
    return `Basic realm="${this.wwwAuthenticateRealm}"`
  }

  protected fail(detail: string): AuthenticationFailed {
    const err = new AuthenticationFailed(detail)
    err.authenticateHeader = this.authenticateHeader()
    return err
  }
}

/** Uses the user set by `RemoteUserMiddleware` (DRF's `RemoteUserAuthentication`). */
export class RemoteUserAuthentication implements BaseAuthentication {
  header = 'Remote-User'

  async authenticate(c: Context): Promise<AuthResult> {
    const username = c.req.header(this.header)
    if (!username) return null
    const user = await authenticate(c, { remoteUser: username })
    if (user && (user as any).isActive !== false) return [user as unknown as RequestUser, null]
    return null
  }
}

/** `Authorization: Bearer <access JWT>` (simplejwt's `JWTAuthentication`). */
export class JWTAuthentication implements BaseAuthentication {
  wwwAuthenticateRealm = 'api'
  /** Token classes accepted (default access tokens). */
  tokenClasses: Array<typeof JWTToken> = [AccessToken]

  async authenticate(c: Context): Promise<AuthResult> {
    const header = c.req.header('authorization')
    if (!header) return null
    const raw = this.getRawToken(header)
    if (raw === null) return null
    const token = await this.getValidatedToken(raw)
    return [(await this.getUser(token)) as unknown as RequestUser, token]
  }

  authenticateHeader(_c?: Context): string {
    return `${jwtSettings().AUTH_HEADER_TYPES[0]} realm="${this.wwwAuthenticateRealm}"`
  }

  getRawToken(header: string): string | null {
    const parts = header.trim().split(/\s+/)
    if (!parts.length || !jwtSettings().AUTH_HEADER_TYPES.includes(parts[0])) return null
    if (parts.length !== 2) {
      const err = new AuthenticationFailed(
        'Authorization header must contain two space-delimited values',
        'bad_authorization_header',
      )
      err.authenticateHeader = this.authenticateHeader()
      throw err
    }
    return parts[1]
  }

  async getValidatedToken(raw: string): Promise<JWTToken> {
    const messages: Array<Record<string, unknown>> = []
    for (const cls of this.tokenClasses) {
      try {
        return await (cls as any).fromString(raw)
      } catch (err) {
        if (!(err instanceof TokenError)) throw err
        messages.push({ token_class: cls.name, token_type: cls.tokenType, message: err.message })
      }
    }
    const err = new InvalidToken('Given token not valid for any token type', 'token_not_valid', messages)
    err.authenticateHeader = this.authenticateHeader()
    throw err
  }

  async getUser(token: JWTToken): Promise<AbstractBaseUser> {
    const s = jwtSettings()
    const userId = token.payload[s.USER_ID_CLAIM]
    if (userId === undefined) throw new InvalidToken('Token contained no recognizable user identification')
    const User = getUserModel()
    const user = await User._defaultManager.filter({ [s.USER_ID_FIELD]: userId }).first()
    if (!user) throw new AuthenticationFailed('User not found', 'user_not_found')
    if ((user as any).isActive === false) throw new AuthenticationFailed('User is inactive', 'user_inactive')
    if (
      s.CHECK_REVOKE_TOKEN &&
      token.payload[s.REVOKE_TOKEN_CLAIM] !== (await passwordRevokeHash(user.password))
    ) {
      throw new AuthenticationFailed("The user's password has been changed.", 'password_changed')
    }
    return user
  }
}

// ---- token views -----------------------------------------------------------------------------------

/** Base for the token endpoints: CSRF exempt (credentials travel in the body), JSON in/out. */
abstract class TokenEndpoint extends View {
  static override csrfExempt = true

  protected async requireFields(c: Context, ...names: string[]): Promise<Record<string, string>> {
    const data = await readData(c)
    const errors: Record<string, string[]> = {}
    const out: Record<string, string> = {}
    for (const n of names) {
      const v = data[n]
      if (typeof v !== 'string' || v === '') errors[n] = ['This field is required.']
      else out[n] = v
    }
    if (Object.keys(errors).length) throw new ValidationError(errors)
    return out
  }
}

/** DRF's `obtain_auth_token`: `POST {username, password}` → `{ token }`. */
export class ObtainAuthTokenView extends TokenEndpoint {
  async post(c: Context): Promise<Response> {
    const User = getUserModel()
    const data = await readData(c)
    const username = (data.username ?? data[User.USERNAME_FIELD]) as string | undefined
    const password = data.password as string | undefined
    const errors: Record<string, string[]> = {}
    if (!username) errors.username = ['This field is required.']
    if (!password) errors.password = ['This field is required.']
    if (Object.keys(errors).length) return json(c, errors, 400)
    const user = await authenticate(c, { username, password })
    if (!user) return json(c, { non_field_errors: ['Unable to log in with provided credentials.'] }, 400)
    const [token] = await Token.objects.getOrCreate({ user: user as any })
    return json(c, { token: token.key })
  }
}

export const obtainAuthToken = ObtainAuthTokenView.asView()

/** `POST {username, password}` → `{ refresh, access }`. */
export class TokenObtainPairView extends TokenEndpoint {
  async post(c: Context): Promise<Response> {
    const User = getUserModel()
    const data = await readData(c)
    const username = (data[User.USERNAME_FIELD] ?? data.username) as string | undefined
    const password = data.password as string | undefined
    const errors: Record<string, string[]> = {}
    if (!username) errors[User.USERNAME_FIELD] = ['This field is required.']
    if (!password) errors.password = ['This field is required.']
    if (Object.keys(errors).length) return json(c, errors, 400)
    const user = await authenticate(c, { username, password })
    if (!user || (user as any).isActive === false) {
      throw new AuthenticationFailed(
        'No active account found with the given credentials',
        'no_active_account',
      )
    }
    const refresh = await RefreshToken.forUser(user)
    if (jwtSettings().UPDATE_LAST_LOGIN && User._meta.getForwardField('lastLogin')) {
      ;(user as any).lastLogin = new Date()
      await user.save({ updateFields: ['lastLogin'] })
    }
    return json(c, { refresh: await refresh.encode(), access: await refresh.accessToken.encode() })
  }
}

/** `POST {refresh}` → `{ access }` (+ a new `refresh` with `ROTATE_REFRESH_TOKENS`). */
export class TokenRefreshView extends TokenEndpoint {
  async post(c: Context): Promise<Response> {
    const { refresh: raw } = await this.requireFields(c, 'refresh')
    const s = jwtSettings()
    let refresh: RefreshToken
    try {
      refresh = await RefreshToken.fromString(raw)
    } catch (err) {
      if (err instanceof TokenError) throw new InvalidToken(err.message)
      throw err
    }
    const userId = refresh.payload[s.USER_ID_CLAIM]
    if (userId !== undefined) {
      const user = await getUserModel()
        ._defaultManager.filter({ [s.USER_ID_FIELD]: userId })
        .first()
      if (!user || (user as any).isActive === false) {
        throw new AuthenticationFailed('No active account found for the given token.', 'no_active_account')
      }
    }
    const out: Record<string, string> = { access: await refresh.accessToken.encode() }
    if (s.ROTATE_REFRESH_TOKENS) {
      if (s.BLACKLIST_AFTER_ROTATION) {
        try {
          await refresh.blacklist()
        } catch (err) {
          if (!(err instanceof TokenError)) throw err
        }
      }
      refresh.setJti()
      refresh.setExp()
      refresh.setIat()
      await refresh.outstand()
      out.refresh = await refresh.encode()
    }
    return json(c, out)
  }
}

/** `POST {token}` → 200 `{}` when valid (any token type), 401 otherwise. */
export class TokenVerifyView extends TokenEndpoint {
  async post(c: Context): Promise<Response> {
    const { token: raw } = await this.requireFields(c, 'token')
    let token: UntypedToken
    try {
      token = await UntypedToken.fromString(raw)
    } catch (err) {
      if (err instanceof TokenError) throw new InvalidToken(err.message)
      throw err
    }
    if (token.payload[jwtSettings().TOKEN_TYPE_CLAIM] === 'refresh') {
      try {
        await new RefreshToken(token.payload, { fresh: false }).checkBlacklist()
      } catch (err) {
        if (err instanceof TokenError) throw new InvalidToken(err.message)
        throw err
      }
    }
    return json(c, {})
  }
}

/** `POST {refresh}` → blacklists it (logout for JWT; needs the `token_blacklist` app). */
export class TokenBlacklistView extends TokenEndpoint {
  async post(c: Context): Promise<Response> {
    const { refresh: raw } = await this.requireFields(c, 'refresh')
    try {
      const refresh = await RefreshToken.fromString(raw)
      await refresh.blacklist()
    } catch (err) {
      if (err instanceof TokenError) throw new InvalidToken(err.message)
      throw err
    }
    return json(c, {})
  }
}

export { AuthenticationFailed, InvalidToken, NotAuthenticated, TokenError } from './errors'
export {
  AccessToken,
  JWTToken,
  jwtSettings,
  RefreshToken,
  tokenPairForUser,
  UntypedToken,
} from './jwt'
