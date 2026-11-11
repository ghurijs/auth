// Django's PasswordResetTokenGenerator (django.contrib.auth.tokens), byte-compatible with Django.
import { tryGetContext } from '@ghuri/core'
import { DEFAULT_PASSWORD_RESET_TIMEOUT } from './settings'
import {
  base36ToInt,
  bytesToHex,
  constantTimeCompare,
  getSecretKey,
  getSecretKeyFallbacks,
  type HashAlgorithm,
  intToBase36,
  saltedHmac,
} from './utils/crypto'

const EPOCH_2001 = Date.UTC(2001, 0, 1)

function pythonDatetime(d: Date): string {
  // str(datetime.replace(microsecond=0, tzinfo=None)) for a UTC datetime
  return d.toISOString().slice(0, 19).replace('T', ' ')
}

/**
 * One-time tokens for password reset links: `<base36 timestamp>-<hmac>`. A token stops working after
 * `PASSWORD_RESET_TIMEOUT` seconds, once the password changes, or once the user logs in again.
 * Times are UTC (Django uses the server's local time — identical on UTC servers).
 */
export class PasswordResetTokenGenerator {
  keySalt = 'django.contrib.auth.tokens.PasswordResetTokenGenerator'
  algorithm: HashAlgorithm = 'sha256'
  /** Override the secret (default `SECRET_KEY`). */
  secret?: string
  /** Override the fallback secrets (default `SECRET_KEY_FALLBACKS`). */
  secretFallbacks?: string[]

  async makeToken(user: any): Promise<string> {
    return this.makeTokenWithTimestamp(user, this.numSeconds(this.now()), this.secret ?? getSecretKey())
  }

  async checkToken(user: any, token: string | null | undefined): Promise<boolean> {
    if (!user || !token) return false
    const parts = token.split('-')
    if (parts.length !== 2) return false
    let ts: number
    try {
      ts = base36ToInt(parts[0])
    } catch {
      return false
    }
    let ok = false
    for (const secret of [
      this.secret ?? getSecretKey(),
      ...(this.secretFallbacks ?? getSecretKeyFallbacks()),
    ]) {
      if (constantTimeCompare(await this.makeTokenWithTimestamp(user, ts, secret), token)) {
        ok = true
        break
      }
    }
    if (!ok) return false
    const timeout =
      (tryGetContext()?.settings.PASSWORD_RESET_TIMEOUT as number | undefined) ??
      DEFAULT_PASSWORD_RESET_TIMEOUT
    return this.numSeconds(this.now()) - ts <= timeout
  }

  protected async makeTokenWithTimestamp(user: any, timestamp: number, secret: string): Promise<string> {
    const hash = bytesToHex(
      await saltedHmac(this.keySalt, this.makeHashValue(user, timestamp), secret, this.algorithm),
    )
    let every2 = ''
    for (let i = 0; i < hash.length; i += 2) every2 += hash[i]
    return `${intToBase36(timestamp)}-${every2}`
  }

  /** Inputs that invalidate the token when they change: pk, password hash, last login, email. */
  protected makeHashValue(user: any, timestamp: number): string {
    const lastLogin = user.lastLogin ? pythonDatetime(new Date(user.lastLogin)) : ''
    const emailField = (user.constructor?.getEmailFieldName?.() as string | undefined) ?? 'email'
    const email = user[emailField] ?? ''
    return `${user.pk}${user.password}${lastLogin}${timestamp}${email}`
  }

  protected numSeconds(d: Date): number {
    return Math.floor((d.getTime() - EPOCH_2001) / 1000)
  }

  protected now(): Date {
    return new Date()
  }
}

export const defaultTokenGenerator = new PasswordResetTokenGenerator()
