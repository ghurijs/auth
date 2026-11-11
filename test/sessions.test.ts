import { getUser, include, json, path, View } from '@ghuri/core'
import type { Context } from 'hono'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import {
  authUrls,
  getSession,
  LoginRequiredMixin,
  loginRequired,
  PermissionRequiredMixin,
  permissionRequired,
  type SessionEngine,
  staffMemberRequired,
  User,
  userLoggedIn,
  userLoggedOut,
} from '../src/index'
import { memoryKV, setupAuthApp } from './helpers'

class Dashboard extends LoginRequiredMixin(View) {
  async get(c: Context) {
    return json(c, { ok: true, user: getUser(c).username })
  }
}

class AddUsers extends PermissionRequiredMixin(View) {
  override permissionRequired = 'auth.add_user'
  async get(c: Context) {
    return json(c, { ok: true })
  }
}

const urls = [
  path('accounts/', include(authUrls)),
  path('counter/', async (c) => {
    const s = getSession(c)
    const n = (await s.get<number>('n', 0)) + 1
    await s.set('n', n)
    return json(c, { n })
  }),
  path('touch/', async (c) => json(c, { has: await getSession(c).has('n') })),
  path('browser-close/', async (c) => {
    const s = getSession(c)
    await s.setExpiry(0)
    await s.set('x', 1)
    return json(c, { close: await s.getExpireAtBrowserClose() })
  }),
  path(
    'protected/',
    loginRequired((c) => json(c, { user: getUser(c).username })),
  ),
  path(
    'perm/',
    permissionRequired('auth.add_user')((c) => json(c, { ok: true })),
  ),
  path(
    'staff/',
    staffMemberRequired((c) => json(c, { ok: true })),
  ),
  path('dash/', Dashboard),
  path('add-users/', AddUsers),
]

const JSON_ACCEPT = { headers: { accept: 'application/json' } }
const engines: SessionEngine[] = ['db', 'kv', 'cache', 'signedCookie']

describe.each(engines)('sessions end to end (SESSION_ENGINE=%s)', (engine) => {
  let s: Awaited<ReturnType<typeof setupAuthApp>>
  const kv = memoryKV()
  beforeAll(async () => {
    s = await setupAuthApp({ urls, settings: { SESSION_ENGINE: engine }, env: { SESSIONS: kv } })
  })
  afterAll(async () => {
    await s?.db.teardown()
  })
  beforeEach(async () => {
    await s.flush()
    kv.store.clear()
    await User.objects.createUser('ann', 'ann@example.com', 'pw-ann-123')
  })

  it('anonymous requests touch no session and set no cookie', async () => {
    const res = await s.client.get('/accounts/me/', JSON_ACCEPT)
    expect(await res.json()).toEqual({ isAuthenticated: false })
    expect(res.headers.get('set-cookie') ?? '').not.toContain('sessionid')
    expect(s.client.getCookie('sessionid')).toBeUndefined()
  })

  it('login → session cookie → authenticated requests → logout', async () => {
    const before = s.client.getCookie('csrftoken')
    const loginRes = await s.client.post('/accounts/login/', {
      json: { username: 'ann', password: 'pw-ann-123' },
    })
    expect(loginRes.status).toBe(200)
    expect(await loginRes.json()).toMatchObject({ user: { username: 'ann', isStaff: false } })
    const cookie = loginRes.headers.get('set-cookie') ?? ''
    expect(cookie).toContain('sessionid=')
    expect(cookie).toMatch(/HttpOnly/i)
    expect(cookie).toMatch(/SameSite=Lax/i)
    expect(cookie).toMatch(/Max-Age=1209600/)
    expect(s.client.getCookie('sessionid')).toBeTruthy()
    expect(s.client.getCookie('csrftoken')).not.toBe(before)
    if (engine === 'kv') expect(kv.store.size).toBe(1)

    const me = await s.client.get('/accounts/me/', JSON_ACCEPT)
    expect(await me.json()).toMatchObject({ isAuthenticated: true, user: { username: 'ann' } })
    expect(me.headers.get('vary')).toContain('Cookie')
    expect((await s.client.get('/protected/', JSON_ACCEPT)).status).toBe(200)
    expect(await (await s.client.get('/dash/', JSON_ACCEPT)).json()).toEqual({ ok: true, user: 'ann' })
    expect((await User.objects.get({ username: 'ann' })).lastLogin).toBeInstanceOf(Date)

    // session data persists across requests alongside the login
    expect(await (await s.client.post('/counter/')).json()).toEqual({ n: 1 })
    expect(await (await s.client.post('/counter/')).json()).toEqual({ n: 2 })

    const out = await s.client.post('/accounts/logout/', { json: {} })
    expect(out.status).toBe(200)
    expect(s.client.getCookie('sessionid')).toBeUndefined()
    expect(await (await s.client.get('/accounts/me/', JSON_ACCEPT)).json()).toEqual({
      isAuthenticated: false,
    })
    if (engine === 'kv') expect(kv.store.size).toBe(0)
  })

  it('rejects bad credentials and inactive users', async () => {
    const bad = await s.client.post('/accounts/login/', { json: { username: 'ann', password: 'nope' } })
    expect(bad.status).toBe(400)
    expect((await bad.json()).errors.__all__[0]).toMatch(/correct username and password/)
    const missing = await s.client.post('/accounts/login/', { json: {} })
    expect((await missing.json()).errors).toMatchObject({ username: ['This field is required.'] })
    await User.objects.filter({ username: 'ann' }).update({ isActive: false })
    const inactive = await s.client.post('/accounts/login/', {
      json: { username: 'ann', password: 'pw-ann-123' },
    })
    expect(inactive.status).toBe(400)
    expect(s.client.getCookie('sessionid')).toBeUndefined()
  })

  it('form login redirects to a safe next URL; HTML clients are sent to the login page', async () => {
    const page = await s.client.get('/protected/', { headers: { accept: 'text/html' } })
    expect(page.status).toBe(302)
    expect(page.headers.get('location')).toBe('/accounts/login/?next=%2Fprotected%2F')
    const form = await s.client.get('/accounts/login/', { headers: { accept: 'text/html' } })
    expect(await form.text()).toContain('name="csrfmiddlewaretoken"')
    const res = await s.client.post('/accounts/login/', {
      form: { username: 'ann', password: 'pw-ann-123', next: '/protected/' },
      headers: { accept: 'text/html' },
    })
    expect(res.status).toBe(302)
    expect(res.headers.get('location')).toBe('/protected/')
    await s.client.post('/accounts/logout/', { json: {} })
    const evil = await s.client.post('/accounts/login/', {
      form: { username: 'ann', password: 'pw-ann-123', next: 'https://evil.example/' },
      headers: { accept: 'text/html' },
    })
    expect(evil.headers.get('location')).toBe('/accounts/profile/')
  })

  it('JSON clients get 401 / 403 from decorators and mixins', async () => {
    expect((await s.client.get('/protected/', JSON_ACCEPT)).status).toBe(401)
    expect((await s.client.get('/dash/', JSON_ACCEPT)).status).toBe(401)
    await s.client.login({ username: 'ann', password: 'pw-ann-123' })
    expect((await s.client.get('/perm/', JSON_ACCEPT)).status).toBe(403)
    expect((await s.client.get('/add-users/', JSON_ACCEPT)).status).toBe(403)
    expect((await s.client.get('/staff/', JSON_ACCEPT)).status).toBe(403)
    const admin = await User.objects.createSuperuser('root', null, 'pw')
    await s.client.forceLogin(admin)
    expect((await s.client.get('/perm/', JSON_ACCEPT)).status).toBe(200)
    expect((await s.client.get('/add-users/', JSON_ACCEPT)).status).toBe(200)
    expect((await s.client.get('/staff/', JSON_ACCEPT)).status).toBe(200)
  })

  it('test client forceLogin / login / logout hooks', async () => {
    const ann = await User.objects.get({ username: 'ann' })
    await s.client.forceLogin(ann)
    expect(await (await s.client.get('/accounts/me/', JSON_ACCEPT)).json()).toMatchObject({
      isAuthenticated: true,
    })
    await s.client.logout()
    expect(await (await s.client.get('/accounts/me/', JSON_ACCEPT)).json()).toEqual({
      isAuthenticated: false,
    })
    expect(await s.client.login({ username: 'ann', password: 'wrong' })).toBe(false)
    expect(await s.client.login({ username: 'ann', password: 'pw-ann-123' })).toBe(true)
    expect(await (await s.client.get('/accounts/me/', JSON_ACCEPT)).json()).toMatchObject({
      isAuthenticated: true,
    })
  })

  it('a password change logs out other sessions but keeps the current one', async () => {
    const other = s.client
    await other.login({ username: 'ann', password: 'pw-ann-123' })
    const { createTestClient } = await import('@ghuri/core/testing')
    const me = createTestClient(s.app, { env: s.env })
    await me.login({ username: 'ann', password: 'pw-ann-123' })
    const res = await me.post('/accounts/password_change/', {
      json: { oldPassword: 'pw-ann-123', newPassword1: 'new-pass-456', newPassword2: 'new-pass-456' },
    })
    expect(res.status).toBe(200)
    expect(await (await me.get('/accounts/me/', JSON_ACCEPT)).json()).toMatchObject({ isAuthenticated: true })
    expect(await (await other.get('/accounts/me/', JSON_ACCEPT)).json()).toEqual({ isAuthenticated: false })
    const wrong = await me.post('/accounts/password_change/', {
      json: { oldPassword: 'pw-ann-123', newPassword1: 'x', newPassword2: 'x' },
    })
    expect(wrong.status).toBe(400)
    expect((await wrong.json()).errors.oldPassword).toBeTruthy()
  })

  it('stores arbitrary session data and honors browser-close expiry', async () => {
    const res = await s.client.post('/browser-close/')
    expect(await res.json()).toEqual({ close: true })
    const cookie = res.headers.get('set-cookie') ?? ''
    expect(cookie).toContain('sessionid=')
    expect(cookie).not.toMatch(/Max-Age/i)
    expect(await (await s.client.post('/counter/')).json()).toEqual({ n: 1 })
    expect(await (await s.client.get('/touch/')).json()).toEqual({ has: true })
  })
})

describe('login/logout signals and CSRF', () => {
  let s: Awaited<ReturnType<typeof setupAuthApp>>
  beforeAll(async () => {
    s = await setupAuthApp({ urls })
  })
  afterAll(async () => {
    await s?.db.teardown()
  })

  it('sends userLoggedIn / userLoggedOut and requires CSRF for the login form', async () => {
    await User.objects.createUser('sig', null, 'pw')
    const events: string[] = []
    const onIn = ({ user }: any) => {
      events.push(`in:${user.username}`)
    }
    const onOut = ({ user }: any) => {
      events.push(`out:${user?.username}`)
    }
    userLoggedIn.connect(onIn)
    userLoggedOut.connect(onOut)
    try {
      const blocked = await s.client.post('/accounts/login/', {
        json: { username: 'sig', password: 'pw' },
        csrf: false,
      })
      expect(blocked.status).toBe(403)
      await s.client.post('/accounts/login/', { json: { username: 'sig', password: 'pw' } })
      await s.client.post('/accounts/logout/', { json: {} })
      expect(events).toEqual(['in:sig', 'out:sig'])
    } finally {
      userLoggedIn.disconnect(onIn)
      userLoggedOut.disconnect(onOut)
    }
  })
})
