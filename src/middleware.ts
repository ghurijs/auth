import { ImproperlyConfigured, Middleware, type RequestUser, settingsFor, setUser } from '@ghuri/core'
import type { Context, Next } from 'hono'
import { deleteCookie, getCookie, setCookie } from 'hono/cookie'
import { authenticate, getSession, getUserFromSession, login, logout } from './auth'
import { loadBackend, RemoteUserBackend } from './backends'
import { UpdateError } from './errors'
import { type SessionBase, sessionConfig } from './sessions/base'
import { getSessionStoreClass } from './sessions/index'

/** Browsers cap cookie lifetimes at 400 days (and Hono refuses longer ones). */
const MAX_COOKIE_AGE = 400 * 24 * 60 * 60

function addVaryCookie(c: Context): void {
  const vary = c.res.headers.get('Vary')
  if (!vary) c.res.headers.set('Vary', 'Cookie')
  else if (!vary.split(',').some((v) => v.trim().toLowerCase() === 'cookie' || v.trim() === '*'))
    c.res.headers.set('Vary', `${vary}, Cookie`)
}

/**
 * Django's SessionMiddleware: loads the session named by the `sessionid` cookie into `c.get('session')`
 * (engine from `SESSION_ENGINE`) and saves it / sets the cookie after the view when it changed.
 */
export class SessionMiddleware extends Middleware {
  async handle(c: Context, next: Next): Promise<void> {
    const config = sessionConfig(settingsFor(c))
    const Store = getSessionStoreClass(config.engine)
    const session = new Store(getCookie(c, config.cookieName) ?? null, config)
    c.set('session', session)
    await next()
    await this.processResponse(c, session)
  }

  protected async processResponse(c: Context, session: SessionBase): Promise<void> {
    const cfg = session.config
    const hadCookie = getCookie(c, cfg.cookieName) !== undefined
    const empty = session.isEmpty()
    if (hadCookie && empty) {
      deleteCookie(c, cfg.cookieName, {
        path: cfg.cookiePath,
        domain: cfg.cookieDomain,
        secure: cfg.cookieSecure,
        sameSite: cfg.cookieSameSite === false ? undefined : cfg.cookieSameSite,
      })
      addVaryCookie(c)
      return
    }
    if (session.accessed) addVaryCookie(c)
    if ((session.modified || cfg.saveEveryRequest) && !empty) {
      if (c.res.status >= 500) return
      let maxAge: number | undefined
      let expires: Date | undefined
      if (!(await session.getExpireAtBrowserClose())) {
        maxAge = Math.min(await session.getExpiryAge(), MAX_COOKIE_AGE)
        expires = new Date(Date.now() + maxAge * 1000)
      }
      try {
        await session.save()
      } catch (err) {
        if (err instanceof UpdateError) {
          throw new ImproperlyConfigured('The request’s session was deleted before the request completed.')
        }
        throw err
      }
      if (session.sessionKey === null) return
      setCookie(c, cfg.cookieName, session.sessionKey, {
        maxAge,
        expires,
        domain: cfg.cookieDomain,
        path: cfg.cookiePath,
        secure: cfg.cookieSecure || cfg.cookieSameSite === 'None' || undefined,
        httpOnly: cfg.cookieHttpOnly || undefined,
        sameSite: cfg.cookieSameSite === false ? undefined : cfg.cookieSameSite,
      })
    }
  }
}

/**
 * Django's AuthenticationMiddleware: sets the request user (`getUser(c)` / `c.get('user')`) from the
 * session. Requests without a session cookie never touch the database. Must come after SessionMiddleware.
 */
export class AuthenticationMiddleware extends Middleware {
  async handle(c: Context, next: Next): Promise<void> {
    if (!c.get('session')) {
      throw new ImproperlyConfigured(
        'AuthenticationMiddleware requires SessionMiddleware to be installed before it in MIDDLEWARE.',
      )
    }
    setUser(c, await getUserFromSession(c))
    await next()
  }
}

/**
 * Logs in the user named by a trusted header set by a proxy / SSO gateway (`REMOTE_USER_HEADER`,
 * default `Remote-User`) using `RemoteUserBackend`. Never use it unless the proxy strips the header
 * from client requests.
 */
export class RemoteUserMiddleware extends Middleware {
  /** Header name; defaults to the `REMOTE_USER_HEADER` setting or `Remote-User`. */
  header?: string
  /** Log the user out when the header disappears (false in `PersistentRemoteUserMiddleware`). */
  forceLogoutIfNoHeader = true

  async handle(c: Context, next: Next): Promise<void> {
    getSession(c)
    const header = this.header ?? (settingsFor(c)?.REMOTE_USER_HEADER as string | undefined) ?? 'Remote-User'
    const username = c.req.header(header)
    const current = c.get('user') as RequestUser | undefined
    if (!username) {
      if (this.forceLogoutIfNoHeader && current?.isAuthenticated && (current as any).backend) {
        if (loadBackend((current as any).backend) instanceof RemoteUserBackend) await logout(c)
      }
      return next()
    }
    if (current?.isAuthenticated) {
      if ((current as any).getUsername?.() === this.cleanUsername(username)) return next()
      await logout(c)
    }
    const user = await authenticate(c, { remoteUser: username })
    if (user) await login(c, user)
    return next()
  }

  cleanUsername(username: string): string {
    return username
  }
}

/** `RemoteUserMiddleware` that keeps the session when the header is absent (login page only behind SSO). */
export class PersistentRemoteUserMiddleware extends RemoteUserMiddleware {
  override forceLogoutIfNoHeader = false
}
