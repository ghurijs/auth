import { runWithContext } from '@ghuri/core'
import { describe, expect, it, vi } from 'vitest'
import {
  checkPassword,
  getHasher,
  identifyHasher,
  isPasswordUsable,
  makePassword,
  makeUnusablePassword,
  PBKDF2PasswordHasher,
  PBKDF2SHA1PasswordHasher,
  pbkdf2,
  ScryptPasswordHasher,
  verifyPassword,
} from '../src/index'
import { pbkdf2Js } from '../src/utils/sha'
import { bareContext } from './helpers'

// Vectors computed with Python's hashlib — exactly what Django's hashers produce.
const DJANGO_PBKDF2_100K = 'pbkdf2_sha256$100000$seasalt$BNZ6eyaNc8qFTJPjrAq99hSYb73EgAdytAtdBg2Sdcc='
const DJANGO_PBKDF2_1M = 'pbkdf2_sha256$1000000$seasalt$r1uLUxoxpP2Ued/qxvmje7UH9PUJBkRrvf9gGPL7Cps='
const DJANGO_PBKDF2_SHA1 = 'pbkdf2_sha1$100000$seasalt$G7Ah/UtVanNc4dqhbApqueZmwLE='
const DJANGO_SCRYPT =
  'scrypt$16384$seasalt$8$1$Qj3+9PPyRjSJIebHnG81TMjsqtaIGxNQG/aEB/NYafTJ7tibgfYz71m0ldQESkXFRkdVCBhhY8mx7rQwite/Pw=='
const PASSWORD = 'lètmein'

describe('Django compatibility', () => {
  it('encodes pbkdf2_sha256 exactly like Django', async () => {
    const h = new PBKDF2PasswordHasher()
    expect(h.iterations).toBe(100_000)
    expect(await h.encode(PASSWORD, 'seasalt')).toBe(DJANGO_PBKDF2_100K)
    expect(await makePassword(PASSWORD, 'seasalt', 'pbkdf2_sha256')).toBe(DJANGO_PBKDF2_100K)
  })

  it('verifies a Django hash with 1,000,000 iterations (and flags it for re-hashing)', async () => {
    expect(await verifyPassword(PASSWORD, DJANGO_PBKDF2_1M)).toEqual([true, true])
    // short salt ('seasalt') → must update, like Django
    expect(await verifyPassword('wrong', DJANGO_PBKDF2_100K)).toEqual([false, true])
  })

  it('verifies pbkdf2_sha1 and scrypt hashes from Django', async () => {
    expect(await checkPassword(PASSWORD, DJANGO_PBKDF2_SHA1)).toBe(true)
    expect(await new PBKDF2SHA1PasswordHasher().encode(PASSWORD, 'seasalt')).toBe(DJANGO_PBKDF2_SHA1)
    expect(await checkPassword(PASSWORD, DJANGO_SCRYPT)).toBe(true)
    expect(await new ScryptPasswordHasher().encode(PASSWORD, 'seasalt')).toBe(DJANGO_SCRYPT)
    expect(await checkPassword('nope', DJANGO_SCRYPT)).toBe(false)
  })

  it('pure-JS PBKDF2 matches WebCrypto (the Workers > 100k iterations fallback)', async () => {
    const enc = new TextEncoder()
    for (const [pw, salt, iters, len, alg] of [
      ['secret', 'salt', 1, 32, 'sha256'],
      ['x'.repeat(100), 'NaCl', 5, 70, 'sha256'],
      ['pässwörd', 'seasalt', 1234, 20, 'sha1'],
      ['p', '', 2, 64, 'sha1'],
    ] as const) {
      const js = pbkdf2Js(alg, enc.encode(pw), enc.encode(salt), iters, len)
      const wc = await pbkdf2(pw, salt, iters, len, alg)
      expect(Buffer.from(js).toString('hex')).toBe(Buffer.from(wc).toString('hex'))
    }
  })

  it('uses the JS PBKDF2 on Workers above 100k iterations', async () => {
    vi.stubGlobal('navigator', { userAgent: 'Cloudflare-Workers' })
    const spy = vi.spyOn(crypto.subtle, 'deriveBits')
    try {
      expect(await checkPassword(PASSWORD, DJANGO_PBKDF2_1M)).toBe(true)
      expect(spy).not.toHaveBeenCalled()
    } finally {
      spy.mockRestore()
      vi.unstubAllGlobals()
    }
  })
})

describe('makePassword / checkPassword', () => {
  it('round-trips with random salts', async () => {
    const a = await makePassword('s3cret')
    const b = await makePassword('s3cret')
    expect(a).not.toBe(b)
    expect(a.startsWith('pbkdf2_sha256$100000$')).toBe(true)
    expect(a.split('$')[2]).toHaveLength(22)
    expect(await checkPassword('s3cret', a)).toBe(true)
    expect(await checkPassword('S3cret', a)).toBe(false)
  })

  it('handles unusable passwords', async () => {
    const u = await makePassword(null)
    expect(u.startsWith('!')).toBe(true)
    expect(u).toHaveLength(41)
    expect(isPasswordUsable(u)).toBe(false)
    expect(isPasswordUsable(makeUnusablePassword())).toBe(false)
    expect(isPasswordUsable(null)).toBe(true)
    expect(isPasswordUsable('pbkdf2_sha256$1$a$b')).toBe(true)
    expect(await checkPassword('', u)).toBe(false)
    expect(await checkPassword(null, await makePassword('x'))).toBe(false)
    expect(await checkPassword('x', null)).toBe(false)
    expect(await checkPassword('x', 'garbage')).toBe(false)
    expect(await checkPassword('x', 'unknown$1$2$3')).toBe(false)
  })

  it('calls the setter when the preferred hasher or its parameters changed', async () => {
    await runWithContext(
      bareContext({
        PASSWORD_HASHERS: [new PBKDF2PasswordHasher({ iterations: 1000 }), ScryptPasswordHasher],
      }),
      async () => {
        const setter = vi.fn()
        expect(await checkPassword(PASSWORD, DJANGO_PBKDF2_100K, setter)).toBe(true)
        expect(setter).toHaveBeenCalledWith(PASSWORD)
        const current = await makePassword('pw')
        expect(current.startsWith('pbkdf2_sha256$1000$')).toBe(true)
        const setter2 = vi.fn()
        expect(await checkPassword('pw', current, setter2)).toBe(true)
        expect(setter2).not.toHaveBeenCalled()
        // algorithm change → upgrade
        const setter3 = vi.fn()
        expect(await checkPassword(PASSWORD, DJANGO_SCRYPT, setter3)).toBe(true)
        expect(setter3).toHaveBeenCalled()
        // wrong password → no upgrade
        const setter4 = vi.fn()
        expect(await checkPassword('bad', DJANGO_PBKDF2_100K, setter4)).toBe(false)
        expect(setter4).not.toHaveBeenCalled()
      },
    )
  })

  it('PASSWORD_HASHERS accepts classes and subclasses with custom iterations', async () => {
    class Strong extends PBKDF2PasswordHasher {
      override iterations = 2000
    }
    await runWithContext(bareContext({ PASSWORD_HASHERS: [Strong] }), async () => {
      expect(getHasher().algorithm).toBe('pbkdf2_sha256')
      expect((await makePassword('a')).split('$')[1]).toBe('2000')
      expect(() => getHasher('scrypt')).toThrow(/Unknown password hashing algorithm/)
      expect(identifyHasher('pbkdf2_sha256$1$x$y')).toBeInstanceOf(Strong)
    })
  })

  it('safeSummary masks salt and hash', () => {
    const s = new PBKDF2PasswordHasher().safeSummary(DJANGO_PBKDF2_100K)
    expect(s).toMatchObject({ algorithm: 'pbkdf2_sha256', iterations: '100000', salt: 'seas***' })
    expect(s.hash.startsWith('BNZ6ey*')).toBe(true)
  })
})
