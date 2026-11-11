import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { getUser, include, json, path } from '@ghuri/core'
import * as orm from '@ghuri/orm'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import {
  AuthenticationMiddleware,
  authUrls,
  isSafeRedirect,
  type PasswordResetInfo,
  PasswordResetView,
  Permission,
  RemoteUserBackend,
  RemoteUserMiddleware,
  SessionMiddleware,
  User,
} from '../src/index'
import { setupAuthApp } from './helpers'

const sent: PasswordResetInfo[] = []
class TestResetView extends PasswordResetView {
  override async sendResetEmail(_c: unknown, info: PasswordResetInfo) {
    sent.push(info)
  }
}

const urls = [
  path('accounts/password_reset/', TestResetView.asView(), { name: 'password_reset' }),
  path('accounts/', include(authUrls)),
  path('whoami/', (c) => json(c, { user: getUser(c).isAuthenticated ? getUser(c).username : null })),
]

describe('password reset flow', () => {
  let s: Awaited<ReturnType<typeof setupAuthApp>>
  beforeAll(async () => {
    s = await setupAuthApp({ urls })
  })
  afterAll(async () => {
    await s?.db.teardown()
  })
  beforeEach(async () => {
    await s.flush()
    sent.length = 0
  })

  it('emails a link, accepts the token once, sets the new password', async () => {
    const ann = await User.objects.createUser('ann', 'ann@example.com', 'old-pw')
    await User.objects.createUser('nopw', 'ann@example.com', null)
    const res = await s.client.post('/accounts/password_reset/', { json: { email: 'ANN@example.com' } })
    expect(res.status).toBe(200)
    expect(sent).toHaveLength(1)
    const info = sent[0]
    expect(info.user.pk).toBe(ann.pk)
    expect(info.url).toBe(`http://testserver/accounts/reset/${info.uid}/${info.token}/`)
    // unknown emails answer the same
    expect(
      (await s.client.post('/accounts/password_reset/', { json: { email: 'nobody@example.com' } })).status,
    ).toBe(200)
    expect(sent).toHaveLength(1)

    const confirmPath = new URL(info.url!).pathname
    expect(
      await (await s.client.get(confirmPath, { headers: { accept: 'application/json' } })).json(),
    ).toEqual({
      validlink: true,
    })
    const mismatch = await s.client.post(confirmPath, {
      json: { newPassword1: 'a-new-pass', newPassword2: 'other' },
    })
    expect(mismatch.status).toBe(400)
    const ok = await s.client.post(confirmPath, {
      json: { newPassword1: 'a-new-pass', newPassword2: 'a-new-pass' },
    })
    expect(ok.status).toBe(200)
    expect(await (await User.objects.get({ pk: ann.pk })).checkPassword('a-new-pass')).toBe(true)
    // the token died with the old password hash
    const reuse = await s.client.post(confirmPath, {
      json: { newPassword1: 'x-new-pass', newPassword2: 'x-new-pass' },
    })
    expect(reuse.status).toBe(400)
    expect(
      (await s.client.get('/accounts/reset/bad/token-x/', { headers: { accept: 'application/json' } }))
        .status,
    ).toBe(400)
  })

  it('logout requires POST', async () => {
    expect(
      (await s.client.get('/accounts/logout/', { headers: { accept: 'application/json' } })).status,
    ).toBe(405)
  })
})

describe('RemoteUserMiddleware', () => {
  let s: Awaited<ReturnType<typeof setupAuthApp>>
  beforeAll(async () => {
    s = await setupAuthApp({
      urls,
      settings: {
        MIDDLEWARE: [SessionMiddleware, AuthenticationMiddleware, RemoteUserMiddleware],
        AUTHENTICATION_BACKENDS: [RemoteUserBackend],
        REMOTE_USER_HEADER: 'X-Forwarded-User',
      },
    })
  })
  afterAll(async () => {
    await s?.db.teardown()
  })

  it('logs in (creating) the header user and logs out when the header disappears', async () => {
    const res = await s.client.get('/whoami/', { headers: { 'X-Forwarded-User': 'sso-user' } })
    expect(await res.json()).toEqual({ user: 'sso-user' })
    const created = await User.objects.get({ username: 'sso-user' })
    expect(created.hasUsablePassword()).toBe(false)
    expect(
      await (await s.client.get('/whoami/', { headers: { 'X-Forwarded-User': 'sso-user' } })).json(),
    ).toEqual({
      user: 'sso-user',
    })
    expect(
      await (await s.client.get('/whoami/', { headers: { 'X-Forwarded-User': 'other' } })).json(),
    ).toEqual({
      user: 'other',
    })
    expect(await (await s.client.get('/whoami/')).json()).toEqual({ user: null })
  })
})

describe('helpers', () => {
  it('isSafeRedirect', () => {
    const hosts = ['testserver']
    expect(isSafeRedirect('/next/', hosts)).toBe(true)
    expect(isSafeRedirect('http://testserver/x', hosts)).toBe(true)
    expect(isSafeRedirect('//evil.com/x', hosts)).toBe(false)
    expect(isSafeRedirect('https://evil.com', hosts)).toBe(false)
    expect(isSafeRedirect('javascript:alert(1)', hosts)).toBe(false)
    expect(isSafeRedirect('/\\evil.com', hosts)).toBe(false)
    expect(isSafeRedirect('', hosts)).toBe(false)
    expect(isSafeRedirect('http://testserver/x', hosts, true)).toBe(false)
  })
})

describe('postMigrate integration', () => {
  const postMigrate = (orm as Record<string, any>).postMigrate
  let s: Awaited<ReturnType<typeof setupAuthApp>>
  beforeAll(async () => {
    s = await setupAuthApp({ urls })
  })
  afterAll(async () => {
    await s?.db.teardown()
  })

  it.skipIf(!postMigrate)('creates permissions when the ORM sends postMigrate', async () => {
    await postMigrate.send(null, { using: 'default', verbosity: 0 })
    expect(await Permission.objects.filter({ codename: 'add_user' }).exists()).toBe(true)
  })
})

describe('Workers safety', () => {
  function files(dir: string): string[] {
    return readdirSync(dir).flatMap((f) => {
      const p = join(dir, f)
      return statSync(p).isDirectory() ? files(p) : [p]
    })
  }

  it('the source never imports Node-only modules or node:crypto', () => {
    const src = join(import.meta.dirname, '..', 'src')
    for (const file of files(src)) {
      const code = readFileSync(file, 'utf8')
      const imports = [...code.matchAll(/(?:from|import)\s*\(?\s*['"]([^'"]+)['"]/g)].map((m) => m[1])
      for (const spec of imports) {
        expect(spec, `${file} imports ${spec}`).not.toMatch(/^(node:|fs$|path$|crypto$|better-sqlite3|pg$)/)
        expect(spec, `${file} imports ${spec}`).not.toMatch(/^@ghuri\/orm\/(sqlite|pglite|testing)/)
      }
    }
  })
})
