// django.contrib.sessions: database-backed sessions (table `django_session`).
import { CharField, DateTimeField, Manager, Model, TextField } from '@ghuri/orm'

export class SessionManager extends Manager<Session> {
  /** Store `data` (already encoded) under `sessionKey`; deletes the row when `data` is empty. */
  async saveEncoded(sessionKey: string, encoded: string | null, expireDate: Date): Promise<Session | null> {
    if (encoded === null) {
      await this.filter({ sessionKey }).delete()
      return null
    }
    const s = new Session({ sessionKey, sessionData: encoded, expireDate })
    await s.save()
    return s
  }
}

/** A stored session: key, signed payload and expiry. */
export class Session extends Model({
  sessionKey: new CharField({ maxLength: 40, primaryKey: true, verboseName: 'session key' }),
  sessionData: new TextField({ verboseName: 'session data' }),
  expireDate: new DateTimeField({ dbIndex: true, verboseName: 'expire date' }),
}) {
  static Meta = { dbTable: 'django_session', verboseName: 'session', verboseNamePlural: 'sessions' }
  static objects = new SessionManager()

  /** Decoded session data. */
  async getDecoded(): Promise<Record<string, unknown>> {
    const { DatabaseSessionStore } = await import('../sessions/db')
    return new DatabaseSessionStore(null).decode(this.sessionData)
  }

  override toString(): string {
    return this.sessionKey
  }
}
