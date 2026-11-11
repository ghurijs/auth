// Runs the hashing / signing / JWT code inside workerd (Miniflare) — the Cloudflare Workers runtime.
import { join } from 'node:path'
import { build } from 'esbuild'
import { Miniflare } from 'miniflare'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'

const WORKER = `
import { runWithContext, createContext } from '@ghuri/core'
import { checkPassword, makePassword, PBKDF2PasswordHasher, ScryptPasswordHasher } from './src/hashers'
import { dumps, loads, Signer } from './src/signing'
import { AccessToken } from './src/jwt'

const DJANGO_1M = 'pbkdf2_sha256$1000000$seasalt$r1uLUxoxpP2Ued/qxvmje7UH9PUJBkRrvf9gGPL7Cps='
const settings = { SECRET_KEY: 'workers-secret', INSTALLED_APPS: [], ROOT_URLCONF: [] }

export default {
  async fetch() {
    return runWithContext(createContext({ env: {}, settings }), async () => {
      let webcryptoLimit = 'none'
      try {
        const key = await crypto.subtle.importKey('raw', new TextEncoder().encode('pw'), 'PBKDF2', false, ['deriveBits'])
        await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: new Uint8Array(8), iterations: 100001 }, key, 256)
      } catch (err) {
        webcryptoLimit = String(err.message || err)
      }
      const fresh = await makePassword('lètmein')
      const token = new AccessToken()
      token.set('user_id', 1)
      const encoded = await token.encode()
      return Response.json({
        userAgent: navigator.userAgent,
        webcryptoLimit,
        django1m: await checkPassword('lètmein', DJANGO_1M),
        django1mWrong: await checkPassword('nope', DJANGO_1M),
        pbkdf2: await new PBKDF2PasswordHasher().encode('lètmein', 'seasalt'),
        scrypt: await checkPassword('lètmein', await new ScryptPasswordHasher({ workFactor: 1024 }).encode('lètmein', 'saltsaltsaltsaltsaltsa')),
        fresh: fresh.split('$').slice(0, 2).join('$'),
        freshOk: await checkPassword('lètmein', fresh),
        signer: await new Signer({ key: 'secret' }).sign('hello'),
        roundTrip: await loads(await dumps({ a: 'ü', list: [1, 2, 3] }, { compress: true })),
        jwt: (await AccessToken.fromString(encoded)).payload.user_id,
      })
    })
  },
}
`

describe('inside workerd (Cloudflare Workers runtime)', () => {
  let mf: Miniflare
  let result: Record<string, any>

  beforeAll(async () => {
    const root = join(import.meta.dirname, '..')
    const out = await build({
      stdin: { contents: WORKER, resolveDir: root, loader: 'ts', sourcefile: 'worker.ts' },
      bundle: true,
      format: 'esm',
      platform: 'browser',
      conditions: ['workerd', 'worker', 'browser'],
      // postgres.js is imported lazily by the ORM and never used here
      external: ['node:*', 'cloudflare:*', 'postgres'],
      write: false,
      logLevel: 'silent',
    })
    mf = new Miniflare({
      modules: true,
      script: out.outputFiles[0].text,
      compatibilityDate: '2025-06-01',
      compatibilityFlags: ['nodejs_compat'],
    })
    const res = await mf.dispatchFetch('http://localhost/')
    result = (await res.json()) as Record<string, any>
  }, 120_000)

  afterAll(async () => {
    await mf?.dispose()
  })

  it('runs on the Workers runtime', () => {
    expect(result.userAgent).toBe('Cloudflare-Workers')
    // Production Workers have refused > 100,000 PBKDF2 iterations; local workerd builds may not.
    expect(typeof result.webcryptoLimit).toBe('string')
  })

  it('still verifies 1,000,000-iteration Django hashes (pure-JS fallback)', () => {
    expect(result.django1m).toBe(true)
    expect(result.django1mWrong).toBe(false)
  })

  it('hashes, signs and issues JWTs identically to Node', () => {
    expect(result.pbkdf2).toBe('pbkdf2_sha256$100000$seasalt$BNZ6eyaNc8qFTJPjrAq99hSYb73EgAdytAtdBg2Sdcc=')
    expect(result.fresh).toBe('pbkdf2_sha256$100000')
    expect(result.freshOk).toBe(true)
    expect(result.scrypt).toBe(true)
    expect(result.signer).toBe('hello:FRBs_KKrjaVe9zJEdlQdiuJ2n9jBEsFOL1Capquoa18')
    expect(result.roundTrip).toEqual({ a: 'ü', list: [1, 2, 3] })
    expect(result.jwt).toBe(1)
  })
})
