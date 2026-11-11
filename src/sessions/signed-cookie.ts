import { dumps, loads } from '../signing'
import { SessionBase, type SessionData } from './base'

const SALT = 'django.contrib.sessions.backends.signed_cookies'

/**
 * `SESSION_ENGINE: 'signedCookie'` — the whole session lives in the cookie, signed with `SECRET_KEY`
 * (no storage at all). Data is readable by the client (not encrypted) and limited to ~4 KB; logging out
 * can't revoke a copied cookie before it expires.
 */
export class SignedCookieSessionStore extends SessionBase {
  protected override validateKey(key: string | null | undefined): key is string {
    return typeof key === 'string' && key.length > 0
  }

  protected async load(): Promise<SessionData> {
    try {
      return (
        (await loads<SessionData>(this._sessionKey!, { salt: SALT, maxAge: this.config.cookieAge })) ?? {}
      )
    } catch {
      // Bad signature or expired: start a new (empty) session.
      await this.create()
      return {}
    }
  }

  async create(): Promise<void> {
    this.modified = true
  }

  async save(_mustCreate = false): Promise<void> {
    this._sessionKey = await dumps(await this.session(), { salt: SALT, compress: true })
    this.modified = true
  }

  async exists(_sessionKey: string): Promise<boolean> {
    return false
  }

  async deleteSession(_sessionKey?: string | null): Promise<void> {
    this._sessionKey = ''
    this._cache = {}
    this.modified = true
  }

  override async cycleKey(): Promise<void> {
    await this.save()
  }
}
