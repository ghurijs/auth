import { IntegrityError } from '@ghuri/orm'
import { CreateError } from '../errors'
import { Session } from '../models/sessions'
import { createWithNewKey, SessionBase, type SessionData } from './base'

/** `SESSION_ENGINE: 'db'` — sessions in the `django_session` table (the `sessions` app must be installed). */
export class DatabaseSessionStore extends SessionBase {
  async exists(sessionKey: string): Promise<boolean> {
    return Session.objects.filter({ sessionKey }).exists()
  }

  protected async load(): Promise<SessionData> {
    const row = await Session.objects
      .filter({ sessionKey: this._sessionKey, expireDate__gt: new Date() })
      .first()
    if (!row) {
      this._sessionKey = null
      return {}
    }
    return this.decode(row.sessionData)
  }

  async create(): Promise<void> {
    await createWithNewKey(this)
  }

  async save(mustCreate = false): Promise<void> {
    if (this._sessionKey === null) return this.create()
    const data = await this.session(mustCreate)
    const obj = new Session({
      sessionKey: this._sessionKey,
      sessionData: await this.encode(data),
      expireDate: await this.getExpiryDate(),
    })
    try {
      await obj.save(mustCreate ? { forceInsert: true } : {})
    } catch (err) {
      if (mustCreate && err instanceof IntegrityError) throw new CreateError('Session key collision')
      throw err
    }
  }

  async deleteSession(sessionKey: string | null = this._sessionKey): Promise<void> {
    if (!sessionKey) return
    await Session.objects.filter({ sessionKey }).delete()
  }

  static override async clearExpired(): Promise<void> {
    await Session.objects.filter({ expireDate__lt: new Date() }).delete()
  }
}
