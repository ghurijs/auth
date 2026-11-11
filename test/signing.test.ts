import { runWithContext } from '@ghuri/core'
import { describe, expect, it, vi } from 'vitest'
import {
  BadSignature,
  dumps,
  loads,
  PasswordResetTokenGenerator,
  SignatureExpired,
  Signer,
  signing,
  TimestampSigner,
} from '../src/index'
import { bareContext, SECRET } from './helpers'

// Produced by Django's algorithm (python3, see the commit message) with key 'secret'.
const PY = {
  signer: 'hello:FRBs_KKrjaVe9zJEdlQdiuJ2n9jBEsFOL1Capquoa18',
  signerSalt: 'hello:qAgCjjlkcBHGqy4A6qV17FI-b_DEPSKILcwx8OoRano',
  dumps: 'eyJhIjoxLCJcdTAwZTkiOiJcdTAwZmMiLCJsaXN0IjpbMSwyLDNdfQ:1xRG2i:WaogW8pg1bIXXCoVYkHmDU46i378JwWUvZlx9z683Io',
  dumpsCompressed: '.eJyrVipJrShRslKqGCZASUcpT8kqrzQnR0cJ6K-SotLUWgDnW2bx:1xRG2i:kilY_xByTNl2l1ZGg1usWd3LP5hjXR3LGRt4qzNTFYM',
  session: 'eyJfYXV0aF91c2VyX2lkIjoiMSIsImZvbyI6ImJhciJ9:1xRG2i:it0oql3zz6MNrPCQPdhtUiOgYikAbUvsTJdsVuIZolw',
  reset: 'bkrfgg-08670e46f1586596443335a4c8a3bb34',
  resetNoLogin: 'bkrfgg-4d4757bf90a4afdc260ec443d68d9c8f',
}

describe('signing (Django-compatible)', () => {
  it('Signer produces the same signatures as Django', async () => {
    expect(await new Signer({ key: 'secret' }).sign('hello')).toBe(PY.signer)
    expect(await new Signer({ key: 'secret', salt: 'my-salt' }).sign('hello')).toBe(PY.signerSalt)
    expect(await new Signer({ key: 'secret' }).unsign(PY.signer)).toBe('hello')
    await expect(new Signer({ key: 'other' }).unsign(PY.signer)).rejects.toBeInstanceOf(BadSignature)
    await expect(new Signer({ key: 'secret' }).unsign('hello:bad')).rejects.toBeInstanceOf(BadSignature)
    await expect(new Signer({ key: 'secret' }).unsign('nosep')).rejects.toThrow(/No ":" found/)
    expect(() => new Signer({ sep: 'abc' })).toThrow(/Unsafe Signer separator/)
  })

  it('loads values made by Django dumps() (plain, compressed, sessions)', async () => {
    expect(await loads(PY.dumps, { key: 'secret' })).toEqual({ a: 1, é: 'ü', list: [1, 2, 3] })
    expect(await loads(PY.dumpsCompressed, { key: 'secret' })).toEqual({ text: 'x'.repeat(200), n: null, t: true })
    expect(await loads(PY.session, { key: 'secret', salt: 'django.contrib.sessions.SessionStore' })).toEqual({
      _auth_user_id: '1',
      foo: 'bar',
    })
    await expect(loads(PY.session, { key: 'secret' })).rejects.toBeInstanceOf(BadSignature)
  })

  it('dumps/loads round-trip with compression, salts and max age', async () => {
    await runWithContext(bareContext(), async () => {
      const big = { items: Array.from({ length: 50 }, (_, i) => `item-${i % 3}`), uni: 'ñ' }
      const s = await dumps(big, { compress: true })
      expect(s.startsWith('.')).toBe(true)
      expect(await loads(s)).toEqual(big)
      const plain = await dumps({ a: 1 })
      expect(plain.startsWith('eyJ')).toBe(true)
      expect(await loads(plain, { maxAge: 10 })).toEqual({ a: 1 })
      await expect(loads(plain, { salt: 'other' })).rejects.toBeInstanceOf(BadSignature)
      const tampered = `${plain.slice(0, 3)}X${plain.slice(4)}`
      await expect(loads(tampered)).rejects.toBeInstanceOf(BadSignature)
      expect(signing.dumps).toBe(dumps)
    })
  })

  it('TimestampSigner enforces maxAge', async () => {
    await runWithContext(bareContext(), async () => {
      const ts = new TimestampSigner()
      const now = Date.now()
      const spy = vi.spyOn(Date, 'now').mockReturnValue(now - 100_000)
      const value = await ts.sign('v')
      spy.mockRestore()
      expect(await ts.unsign(value)).toBe('v')
      expect(await ts.unsign(value, 200)).toBe('v')
      await expect(ts.unsign(value, 50)).rejects.toBeInstanceOf(SignatureExpired)
    })
  })

  it('accepts SECRET_KEY_FALLBACKS when unsigning', async () => {
    const old = await runWithContext(bareContext({ SECRET_KEY: 'old-key' }), () => new Signer().sign('x'))
    await runWithContext(bareContext({ SECRET_KEY: SECRET, SECRET_KEY_FALLBACKS: ['old-key'] }), async () => {
      expect(await new Signer().unsign(old)).toBe('x')
    })
    await runWithContext(bareContext({ SECRET_KEY: SECRET }), async () => {
      await expect(new Signer().unsign(old)).rejects.toBeInstanceOf(BadSignature)
    })
  })
})

describe('PasswordResetTokenGenerator (Django-compatible)', () => {
  class FixedClock extends PasswordResetTokenGenerator {
    at = Date.UTC(2001, 0, 1) + 700_000_000 * 1000
    protected override now(): Date {
      return new Date(this.at)
    }
  }
  const user = {
    pk: 1,
    password: 'pbkdf2_sha256$1000$seasalt$abc=',
    lastLogin: new Date(Date.UTC(2024, 0, 2, 3, 4, 5, 678)),
    email: 'ann@example.com',
  }

  it('makes the same token as Django', async () => {
    const g = new FixedClock()
    g.secret = 'secret'
    expect(await g.makeToken(user)).toBe(PY.reset)
    expect(await g.makeToken({ ...user, lastLogin: null, email: null })).toBe(PY.resetNoLogin)
  })

  it('checks tokens: validity, tampering, invalidation and expiry', async () => {
    await runWithContext(bareContext({ PASSWORD_RESET_TIMEOUT: 3600 }), async () => {
      const g = new FixedClock()
      const token = await g.makeToken(user)
      expect(await g.checkToken(user, token)).toBe(true)
      expect(await g.checkToken(user, `${token}x`)).toBe(false)
      expect(await g.checkToken(user, 'nonsense')).toBe(false)
      expect(await g.checkToken(user, '!!!-abc')).toBe(false)
      expect(await g.checkToken(null, token)).toBe(false)
      expect(await g.checkToken({ ...user, password: 'changed' }, token)).toBe(false)
      expect(await g.checkToken({ ...user, lastLogin: new Date() }, token)).toBe(false)
      g.at += 3599 * 1000
      expect(await g.checkToken(user, token)).toBe(true)
      g.at += 2000
      expect(await g.checkToken(user, token)).toBe(false)
    })
  })
})
