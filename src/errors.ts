import { GhuriError, HttpError, registerExceptionHandler, wantsJson } from '@ghuri/core'

/**
 * Base of auth HTTP errors (401/403). Shaped like DRF's `APIException` (`status`, `detail`, `code`) so
 * `@ghuri/rest` can map it structurally; without rest, Ghuri renders `{ detail, code }`.
 */
export class AuthHttpError extends HttpError {
  readonly detail: string
  readonly code: string
  /** `WWW-Authenticate` header value for 401 responses. */
  authenticateHeader?: string

  constructor(detail: string, code: string, status: number) {
    super(detail)
    this.detail = detail
    this.code = code
    this.status = status
  }

  /** Alias used by some exception handlers. */
  get statusCode(): number {
    return this.status
  }
}

/** Credentials were sent but are invalid (401). DRF's `AuthenticationFailed`. */
export class AuthenticationFailed extends AuthHttpError {
  constructor(detail = 'Incorrect authentication credentials.', code = 'authentication_failed') {
    super(detail, code, 401)
  }
}

/** No credentials were sent (401). DRF's `NotAuthenticated`. */
export class NotAuthenticated extends AuthHttpError {
  constructor(detail = 'Authentication credentials were not provided.', code = 'not_authenticated') {
    super(detail, code, 401)
  }
}

/** JWT is invalid or expired (401). simplejwt's `InvalidToken`. */
export class InvalidToken extends AuthenticationFailed {
  readonly messages?: Array<Record<string, unknown>>
  constructor(
    detail = 'Token is invalid or expired',
    code = 'token_not_valid',
    messages?: Array<Record<string, unknown>>,
  ) {
    super(detail, code)
    this.messages = messages
  }
}

/** Errors raised while parsing / validating JWTs (simplejwt's `TokenError`). */
export class TokenError extends GhuriError {}
export class ExpiredTokenError extends TokenError {}

/** Session couldn't be created (key collision). */
export class CreateError extends GhuriError {}
/** Session was deleted while the request was running. */
export class UpdateError extends GhuriError {}

const KEY = Symbol.for('ghuri.auth.exceptionHandler')
const g = globalThis as any
if (!g[KEY]) {
  g[KEY] = true
  registerExceptionHandler(AuthHttpError, (err: AuthHttpError, c) => {
    const headers: Record<string, string> = {}
    if (err.status === 401 && err.authenticateHeader) headers['WWW-Authenticate'] = err.authenticateHeader
    if (!wantsJson(c)) {
      if (!Object.keys(headers).length) return undefined
      return c.text(err.detail, err.status as any, headers)
    }
    const body: Record<string, unknown> = { detail: err.detail, code: err.code }
    if (err instanceof InvalidToken && err.messages) body.messages = err.messages
    return c.json(body, err.status as any, headers)
  })
}
