// JSON-first auth views (Django's django.contrib.auth.views) and `authUrls`.
import {
  getCsrfToken,
  getHost,
  getUser,
  json,
  kwargs,
  path,
  resolveUrl,
  settingsFor,
  urlpatterns,
  ValidationError,
  View,
  wantsJson,
} from '@ghuri/core'
import type { Context } from 'hono'
import { authenticate, login, logout, REDIRECT_FIELD_NAME, updateSessionAuthHash } from './auth'
import { LoginRequiredMixin } from './decorators'
import type { AbstractBaseUser } from './models/auth'
import { validatePassword } from './password-validation'
import { DEFAULT_LOGIN_REDIRECT_URL } from './settings'
import { defaultTokenGenerator, type PasswordResetTokenGenerator } from './tokens'
import { getUserModel } from './user-model'
import { urlsafeBase64Decode, urlsafeBase64Encode } from './utils/crypto'

/** Request body as a plain object (JSON, urlencoded or multipart). */
export async function readData(c: Context): Promise<Record<string, unknown>> {
  const ct = c.req.header('content-type') ?? ''
  try {
    if (ct.includes('application/json')) return ((await c.req.json()) as Record<string, unknown>) ?? {}
    if (ct.includes('application/x-www-form-urlencoded') || ct.includes('multipart/form-data')) {
      return (await c.req.parseBody()) as Record<string, unknown>
    }
  } catch {
    return {}
  }
  return {}
}

function str(v: unknown): string | undefined {
  return typeof v === 'string' ? v : undefined
}

function escapeHtml(v: unknown): string {
  return String(v).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;')
}

/** Is `url` a safe redirect target (relative, or same host)? Django's `url_has_allowed_host_and_scheme`. */
export function isSafeRedirect(
  url: string | undefined | null,
  allowedHosts: string[],
  requireHttps = false,
): url is string {
  if (!url) return false
  const u = url.trim()
  if (u.startsWith('///') || u.startsWith('\\') || [...u].some((ch) => ch.charCodeAt(0) < 0x20)) return false
  if (u.startsWith('//')) {
    try {
      return allowedHosts.includes(new URL(`http:${u}`).host)
    } catch {
      return false
    }
  }
  if (/^[a-z][a-z0-9+.-]*:/i.test(u)) {
    try {
      const parsed = new URL(u)
      if (!['http:', 'https:'].includes(parsed.protocol)) return false
      if (requireHttps && parsed.protocol !== 'https:') return false
      return allowedHosts.includes(parsed.host)
    } catch {
      return false
    }
  }
  return !u.startsWith('/\\')
}

function userInfo(user: any): Record<string, unknown> {
  const M = user.constructor as any
  return {
    pk: user.pk,
    [M.USERNAME_FIELD ?? 'username']: user.getUsername?.() ?? user.username,
    isStaff: user.isStaff,
    isSuperuser: user.isSuperuser,
  }
}

function loginPage(c: Context, error?: string, status = 200): Response {
  const next = c.req.query(REDIRECT_FIELD_NAME) ?? ''
  const html = `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Log in</title></head><body>
<h1>Log in</h1>${error ? `<p class="errornote">${escapeHtml(error)}</p>` : ''}
<form method="post"><input type="hidden" name="csrfmiddlewaretoken" value="${escapeHtml(getCsrfToken(c))}">
<p><label>Username: <input name="username" autocomplete="username" required autofocus></label></p>
<p><label>Password: <input type="password" name="password" autocomplete="current-password" required></label></p>
<input type="hidden" name="next" value="${escapeHtml(next)}"><button type="submit">Log in</button></form></body></html>`
  return c.html(html, status as any)
}

/**
 * `POST {username, password}` (JSON or form) → logs in. JSON clients get `{ user }`; forms are redirected
 * to `next` or `LOGIN_REDIRECT_URL`. `GET` returns `{ isAuthenticated, csrfToken, user? }` (JSON) or a minimal form.
 */
export class LoginView extends View {
  /** Where to go after login when no safe `next` is given (default `LOGIN_REDIRECT_URL`). */
  nextPage?: string
  invalidLoginMessage =
    'Please enter a correct username and password. Note that both fields may be case-sensitive.'

  async get(c: Context): Promise<Response> {
    const user = getUser(c)
    if (wantsJson(c)) {
      return json(c, {
        isAuthenticated: user.isAuthenticated,
        csrfToken: getCsrfToken(c),
        ...(user.isAuthenticated ? { user: userInfo(user) } : {}),
      })
    }
    return loginPage(c)
  }

  async post(c: Context): Promise<Response> {
    const data = await readData(c)
    const User = getUserModel()
    const username = str(data.username) ?? str(data[User.USERNAME_FIELD])
    const password = str(data.password)
    const errors: Record<string, string[]> = {}
    if (!username) errors[User.USERNAME_FIELD] = ['This field is required.']
    if (!password) errors.password = ['This field is required.']
    let user: AbstractBaseUser | null = null
    if (!Object.keys(errors).length) {
      user = await authenticate(c, { username, password })
      if (!user) errors.__all__ = [this.invalidLoginMessage]
    }
    if (!user) {
      if (wantsJson(c)) throw new ValidationError(errors)
      return loginPage(c, Object.values(errors).flat().join(' '), 400)
    }
    await login(c, user)
    if (wantsJson(c)) return json(c, { user: userInfo(user) })
    return c.redirect(
      this.successUrl(c, str(data[REDIRECT_FIELD_NAME]) ?? c.req.query(REDIRECT_FIELD_NAME)),
      302,
    )
  }

  successUrl(c: Context, next?: string): string {
    if (isSafeRedirect(next, [getHost(c)])) return next
    return resolveUrl(
      this.nextPage ??
        (settingsFor(c)?.LOGIN_REDIRECT_URL as string | undefined) ??
        DEFAULT_LOGIN_REDIRECT_URL,
    )
  }
}

/** `POST` → logs out (GET is not allowed, like Django 5). JSON `{ detail }` or redirect. */
export class LogoutView extends View {
  nextPage?: string

  async post(c: Context): Promise<Response> {
    await logout(c)
    if (wantsJson(c)) return json(c, { detail: 'Successfully logged out.' })
    const data = await readData(c)
    const next = str(data[REDIRECT_FIELD_NAME]) ?? c.req.query(REDIRECT_FIELD_NAME)
    if (isSafeRedirect(next, [getHost(c)])) return c.redirect(next, 302)
    const target = this.nextPage ?? (settingsFor(c)?.LOGOUT_REDIRECT_URL as string | null | undefined)
    if (target) return c.redirect(resolveUrl(target), 302)
    return c.html(
      '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Logged out</title></head><body><p>You have been logged out.</p></body></html>',
    )
  }
}

/** `POST {oldPassword, newPassword1, newPassword2}` (login required) → changes the password, keeps the session. */
export class PasswordChangeView extends LoginRequiredMixin(View) {
  async post(c: Context): Promise<Response> {
    const data = await readData(c)
    const user = getUser(c) as unknown as AbstractBaseUser
    const oldPassword = str(data.oldPassword) ?? str(data.old_password) ?? ''
    const p1 = str(data.newPassword1) ?? str(data.new_password1) ?? ''
    const p2 = str(data.newPassword2) ?? str(data.new_password2) ?? ''
    if (!(await user.checkPassword(oldPassword))) {
      throw new ValidationError({
        oldPassword: ['Your old password was entered incorrectly. Please enter it again.'],
      })
    }
    await setNewPassword(user, p1, p2)
    await updateSessionAuthHash(c, user)
    return json(c, { detail: 'Password changed.' })
  }
}

async function setNewPassword(user: AbstractBaseUser, p1: string, p2: string): Promise<void> {
  if (!p1) throw new ValidationError({ newPassword1: ['This field is required.'] })
  if (p1 !== p2) throw new ValidationError({ newPassword2: ['The two password fields didn’t match.'] })
  try {
    await validatePassword(p2, user)
  } catch (err) {
    if (err instanceof ValidationError) throw new ValidationError({ newPassword2: err.messages })
    throw err
  }
  await user.setPassword(p1)
  await user.save()
}

export interface PasswordResetInfo {
  user: AbstractBaseUser
  email: string
  /** `urlsafeBase64Encode(user.pk)` */
  uid: string
  token: string
  /** Absolute URL of the reset-confirm view (when `authUrls` are mounted). */
  url?: string
}

/**
 * `POST {email}` → for every active user with that email and a usable password, builds a reset token and
 * calls `sendResetEmail(c, info)` (override it, or pass it to `asView()`). Always answers 200 so the
 * endpoint can't be used to discover accounts.
 */
export class PasswordResetView extends View {
  tokenGenerator: PasswordResetTokenGenerator = defaultTokenGenerator
  /** URL name of the confirm view (used to build `info.url`). */
  confirmUrlName = 'password_reset_confirm'

  /** Deliver the reset link. The default only logs it in DEBUG. */
  async sendResetEmail(c: Context, info: PasswordResetInfo): Promise<void> {
    if (settingsFor(c)?.DEBUG)
      console.info(`[password reset] ${info.email}: ${info.url ?? `${info.uid}/${info.token}`}`)
    else console.warn('PasswordResetView.sendResetEmail is not configured; no email was sent.')
  }

  async post(c: Context): Promise<Response> {
    const data = await readData(c)
    const email = str(data.email)?.trim()
    if (!email) throw new ValidationError({ email: ['This field is required.'] })
    const User = getUserModel()
    const emailField = User.getEmailFieldName()
    const candidates = await User._defaultManager.filter({ [`${emailField}__iexact`]: email })
    for (const user of candidates as any[]) {
      if (user.isActive === false || !user.hasUsablePassword()) continue
      if (String(user[emailField] ?? '').toLowerCase() !== email.toLowerCase()) continue
      const uid = urlsafeBase64Encode(String(user.pk))
      const token = await this.tokenGenerator.makeToken(user)
      let url: string | undefined
      try {
        const origin = new URL(c.req.url).origin
        url = origin + resolveUrl(this.confirmUrlName, { uidb64: uid, token })
      } catch {
        url = undefined
      }
      await this.sendResetEmail(c, { user, email: user[emailField], uid, token, url })
    }
    return json(c, { detail: 'Password reset e-mail has been sent.' })
  }
}

/** `GET` checks the link; `POST {newPassword1, newPassword2}` sets the new password. URL: `<uidb64>/<token>/`. */
export class PasswordResetConfirmView extends View {
  tokenGenerator: PasswordResetTokenGenerator = defaultTokenGenerator
  /** Log the user in after a successful reset. */
  postResetLogin = false

  protected async getUserFromUid(uidb64: string): Promise<AbstractBaseUser | null> {
    const User = getUserModel()
    try {
      const pk = User._meta.pk.toPython(urlsafeBase64Decode(uidb64))
      return await User._defaultManager.get({ pk })
    } catch {
      return null
    }
  }

  protected async validLink(c: Context): Promise<AbstractBaseUser | null> {
    const kw = kwargs<{ uidb64: string; token: string }>(c)
    const user = await this.getUserFromUid(kw.uidb64)
    if (!user || !(await this.tokenGenerator.checkToken(user, kw.token))) return null
    return user
  }

  async get(c: Context): Promise<Response> {
    const user = await this.validLink(c)
    return json(c, { validlink: !!user }, user ? 200 : 400)
  }

  async post(c: Context): Promise<Response> {
    const user = await this.validLink(c)
    if (!user)
      return json(
        c,
        {
          detail: 'The password reset link was invalid, possibly because it has already been used.',
          validlink: false,
        },
        400,
      )
    const data = await readData(c)
    await setNewPassword(
      user,
      str(data.newPassword1) ?? str(data.new_password1) ?? '',
      str(data.newPassword2) ?? str(data.new_password2) ?? '',
    )
    if (this.postResetLogin) await login(c, user)
    return json(c, { detail: 'Password has been reset.' })
  }
}

/** Current user (`GET`): `{ isAuthenticated, user? }`. */
export class WhoAmIView extends View {
  async get(c: Context): Promise<Response> {
    const user = getUser(c)
    return json(c, {
      isAuthenticated: user.isAuthenticated,
      ...(user.isAuthenticated ? { user: userInfo(user) } : {}),
    })
  }
}

/**
 * Django's `django.contrib.auth.urls`, JSON-first:
 * `path('accounts/', include(authUrls))` → `login/`, `logout/`, `password_change/`, `password_reset/`,
 * `reset/<uidb64>/<token>/`, `me/`.
 */
export const authUrls = urlpatterns(undefined, [
  path('login/', LoginView.asView(), { name: 'login' }),
  path('logout/', LogoutView.asView(), { name: 'logout' }),
  path('password_change/', PasswordChangeView.asView(), { name: 'password_change' }),
  path('password_reset/', PasswordResetView.asView(), { name: 'password_reset' }),
  path('reset/<uidb64>/<token>/', PasswordResetConfirmView.asView(), { name: 'password_reset_confirm' }),
  path('me/', WhoAmIView.asView(), { name: 'whoami' }),
])
