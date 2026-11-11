// View decorators and class-based-view mixins (Django's login_required & co, LoginRequiredMixin & co).
import {
  getUser,
  json,
  NoReverseMatch,
  PermissionDenied,
  type RequestUser,
  resolveUrl,
  settingsFor,
  type View,
  type ViewFunction,
  wantsJson,
} from '@ghuri/core'
import type { Context } from 'hono'
import { REDIRECT_FIELD_NAME } from './auth'
import { DEFAULT_LOGIN_URL } from './settings'

export interface AccessOptions {
  /** URL or URL name of the login page (default `LOGIN_URL`, `/accounts/login/`). */
  loginUrl?: string
  /** Query parameter carrying the original URL (default `next`). */
  redirectFieldName?: string | null
  /** Respond 403 instead of redirecting to the login page (used for logged-in users anyway). */
  raiseException?: boolean
}

export type UserTest = (user: RequestUser, c: Context) => boolean | Promise<boolean>

/** Django's `redirect_to_login`: `/accounts/login/?next=/current/path/`. */
export function redirectToLogin(
  c: Context,
  next: string,
  loginUrl?: string,
  redirectFieldName: string | null = REDIRECT_FIELD_NAME,
): Response {
  let target = loginUrl ?? (settingsFor(c)?.LOGIN_URL as string | undefined) ?? DEFAULT_LOGIN_URL
  try {
    target = resolveUrl(target)
  } catch (err) {
    if (!(err instanceof NoReverseMatch)) throw err
  }
  const url = new URL(target, 'http://placeholder')
  if (redirectFieldName) url.searchParams.set(redirectFieldName, next)
  const absolute = /^[a-z][a-z0-9+.-]*:\/\//i.test(target)
  return c.redirect(absolute ? url.toString() : `${url.pathname}${url.search}${url.hash}`, 302)
}

function currentPath(c: Context): string {
  const u = new URL(c.req.url)
  return u.pathname + u.search
}

/**
 * What happens when access is denied: JSON clients get 401 (anonymous) / 403 (authenticated); browsers
 * are redirected to the login page (anonymous) or get 403.
 */
export function denyAccess(c: Context, opts: AccessOptions = {}, message?: string): Response {
  const user = getUser(c)
  if (user.isAuthenticated || opts.raiseException) {
    if (wantsJson(c) && !user.isAuthenticated) {
      return json(c, { detail: message ?? 'Authentication credentials were not provided.' }, 401)
    }
    throw new PermissionDenied(message || 'You do not have permission to perform this action.')
  }
  if (wantsJson(c)) return json(c, { detail: 'Authentication credentials were not provided.' }, 401)
  return redirectToLogin(
    c,
    currentPath(c),
    opts.loginUrl,
    opts.redirectFieldName === undefined ? REDIRECT_FIELD_NAME : opts.redirectFieldName,
  )
}

function wrap(view: ViewFunction, check: (c: Context) => Promise<Response | null>): ViewFunction {
  const wrapped: ViewFunction = async (c) => (await check(c)) ?? view(c)
  // keep viewClass / csrfExempt markers
  Object.assign(wrapped, view)
  Object.defineProperty(wrapped, 'name', { value: view.name })
  return wrapped
}

/**
 * Only let users passing `test` through: `userPassesTest((u) => u.isStaff)(view)`.
 */
export function userPassesTest(test: UserTest, opts: AccessOptions = {}) {
  return (view: ViewFunction): ViewFunction =>
    wrap(view, async (c) => ((await test(getUser(c), c)) ? null : denyAccess(c, opts)))
}

/**
 * Require an authenticated user: `loginRequired(view)` or `loginRequired({ loginUrl })(view)`.
 */
export function loginRequired(view: ViewFunction, opts?: AccessOptions): ViewFunction
export function loginRequired(opts?: AccessOptions): (view: ViewFunction) => ViewFunction
export function loginRequired(viewOrOpts?: ViewFunction | AccessOptions, opts: AccessOptions = {}): any {
  if (typeof viewOrOpts === 'function') return userPassesTest((u) => u.isAuthenticated, opts)(viewOrOpts)
  return userPassesTest((u) => u.isAuthenticated, viewOrOpts ?? {})
}

/**
 * Require one or more permissions: `permissionRequired('blog.add_post')(view)`. Anonymous users go to the
 * login page; authenticated users without the permission get 403 (set `raiseException` to always 403).
 */
export function permissionRequired(perm: string | string[], opts: AccessOptions = {}) {
  const perms = Array.isArray(perm) ? perm : [perm]
  return (view: ViewFunction): ViewFunction =>
    wrap(view, async (c) => {
      const user = getUser(c)
      for (const p of perms) if (!(await user.hasPerm(p))) return denyAccess(c, opts)
      return null
    })
}

/** Active staff members only (redirects others to `admin:login`, falling back to `LOGIN_URL`). */
export function staffMemberRequired(view: ViewFunction, opts: AccessOptions = {}): ViewFunction {
  return wrap(view, async (c) => {
    const user = getUser(c)
    if (user.isActive && user.isStaff) return null
    let loginUrl = opts.loginUrl
    if (!loginUrl) {
      try {
        loginUrl = resolveUrl('admin:login')
      } catch {
        loginUrl = undefined
      }
    }
    return denyAccess(c, { ...opts, loginUrl })
  })
}

// ---- class-based view mixins -------------------------------------------------------------------------

type ViewCtor = abstract new (...args: any[]) => View

/** Shared behavior of the access mixins (Django's `AccessMixin`). */
export function AccessMixin<B extends ViewCtor>(Base: B) {
  abstract class Access extends Base {
    loginUrl?: string
    redirectFieldName: string | null = REDIRECT_FIELD_NAME
    raiseException = false
    permissionDeniedMessage = ''

    handleNoPermission(c: Context): Response {
      return denyAccess(
        c,
        {
          loginUrl: this.loginUrl,
          redirectFieldName: this.redirectFieldName,
          raiseException: this.raiseException,
        },
        this.permissionDeniedMessage || undefined,
      )
    }
  }
  return Access
}

/** `class Dashboard extends LoginRequiredMixin(View) { … }` */
export function LoginRequiredMixin<B extends ViewCtor>(Base: B) {
  abstract class LoginRequired extends AccessMixin(Base) {
    override async dispatch(c: Context): Promise<Response> {
      if (!getUser(c).isAuthenticated) return this.handleNoPermission(c)
      return super.dispatch(c)
    }
  }
  return LoginRequired
}

/** `class Edit extends PermissionRequiredMixin(View) { permissionRequired = 'blog.change_post' }` */
export function PermissionRequiredMixin<B extends ViewCtor>(Base: B) {
  abstract class PermissionRequired extends AccessMixin(Base) {
    permissionRequired: string | string[] | null = null

    getPermissionRequired(): string[] {
      if (this.permissionRequired === null) {
        throw new TypeError(`${this.constructor.name} is missing the permissionRequired attribute.`)
      }
      return Array.isArray(this.permissionRequired) ? this.permissionRequired : [this.permissionRequired]
    }

    async hasPermission(c: Context): Promise<boolean> {
      const user = getUser(c)
      for (const p of this.getPermissionRequired()) if (!(await user.hasPerm(p))) return false
      return true
    }

    override async dispatch(c: Context): Promise<Response> {
      if (!(await this.hasPermission(c))) return this.handleNoPermission(c)
      return super.dispatch(c)
    }
  }
  return PermissionRequired
}

/** `class X extends UserPassesTestMixin(View) { testFunc(c) { return getUser(c).isStaff } }` */
export function UserPassesTestMixin<B extends ViewCtor>(Base: B) {
  abstract class UserPassesTest extends AccessMixin(Base) {
    testFunc(_c: Context): boolean | Promise<boolean> {
      throw new TypeError(`${this.constructor.name} is missing the implementation of testFunc().`)
    }

    override async dispatch(c: Context): Promise<Response> {
      if (!(await this.testFunc(c))) return this.handleNoPermission(c)
      return super.dispatch(c)
    }
  }
  return UserPassesTest
}
