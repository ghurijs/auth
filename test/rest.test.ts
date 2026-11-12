import { csrfExempt, json, path } from '@ghuri/core'
import type { Context } from 'hono'
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest'
import { AccessToken, BlacklistedToken, OutstandingToken, RefreshToken, Token, User } from '../src/index'
import {
  type BaseAuthentication,
  BasicAuthentication,
  JWTAuthentication,
  obtainAuthToken,
  SessionAuthentication,
  TokenAuthentication,
  TokenBlacklistView,
  TokenObtainPairView,
  TokenRefreshView,
  TokenVerifyView,
} from '../src/rest'
import { setupAuthApp } from './helpers'

/** A tiny stand-in for @ghuri/rest: run one authentication class, report the user. */
function authView(Cls: new () => BaseAuthentication) {
  return csrfExempt(async (c: Context) => {
    const auth = new Cls()
    const result = await auth.authenticate(c)
    if (!result) {
      const header = auth.authenticateHeader?.(c)
      return json(c, { user: null }, header ? 401 : 200, header ? { 'WWW-Authenticate': header } : undefined)
    }
    const [user, token] = result
    return json(c, { user: (user as any).username, token: token ? 'yes' : 'no' })
  })
}

const urls = [
  path('api/session/', authView(SessionAuthentication)),
  path('api/token/', authView(TokenAuthentication)),
  path('api/jwt/', authView(JWTAuthentication)),
  path('api/basic/', authView(BasicAuthentication)),
  path('api/auth-token/', obtainAuthToken),
  path('api/jwt/obtain/', TokenObtainPairView.asView()),
  path('api/jwt/refresh/', TokenRefreshView.asView()),
  path('api/jwt/verify/', TokenVerifyView.asView()),
  path('api/jwt/blacklist/', TokenBlacklistView.asView()),
]

const JSON_ACCEPT = { accept: 'application/json' }

describe('REST authentication', () => {
  let s: Awaited<ReturnType<typeof setupAuthApp>>
  let ann: User
  beforeAll(async () => {
    s = await setupAuthApp({
      urls,
      settings: { JWT: { ROTATE_REFRESH_TOKENS: true, BLACKLIST_AFTER_ROTATION: true } },
    })
  })
  afterAll(async () => {
    await s?.db.teardown()
  })
  beforeEach(async () => {
    await s.flush()
    ann = await User.objects.createUser('ann', 'ann@example.com', 'pw-ann')
  })

  it('SessionAuthentication enforces CSRF for authenticated unsafe requests only', async () => {
    expect(await (await s.client.post('/api/session/', { csrf: false })).json()).toEqual({ user: null })
    await s.client.forceLogin(ann)
    expect(await (await s.client.get('/api/session/')).json()).toEqual({ user: 'ann', token: 'no' })
    const blocked = await s.client.post('/api/session/', { csrf: false, headers: JSON_ACCEPT })
    expect(blocked.status).toBe(403)
    expect((await blocked.json()).detail).toMatch(/CSRF/)
    const ok = await s.client.post('/api/session/')
    expect(await ok.json()).toEqual({ user: 'ann', token: 'no' })
    await User.objects.filter({ pk: ann.pk }).update({ isActive: false })
    expect(await (await s.client.get('/api/session/')).json()).toEqual({ user: null })
  })

  it('obtainAuthToken + TokenAuthentication', async () => {
    const bad = await s.client.post('/api/auth-token/', { json: { username: 'ann', password: 'x' } })
    expect(bad.status).toBe(400)
    expect(await bad.json()).toEqual({ non_field_errors: ['Unable to log in with provided credentials.'] })
    const missing = await s.client.post('/api/auth-token/', { json: {} })
    expect(await missing.json()).toEqual({
      username: ['This field is required.'],
      password: ['This field is required.'],
    })
    const res = await s.client.post('/api/auth-token/', {
      json: { username: 'ann', password: 'pw-ann' },
      csrf: false,
    })
    const { token } = await res.json()
    expect(token).toMatch(/^[0-9a-f]{40}$/)
    const again = await (
      await s.client.post('/api/auth-token/', { json: { username: 'ann', password: 'pw-ann' } })
    ).json()
    expect(again.token).toBe(token)
    expect(await Token.objects.count()).toBe(1)

    const ok = await s.client.get('/api/token/', { headers: { authorization: `Token ${token}` } })
    expect(await ok.json()).toEqual({ user: 'ann', token: 'yes' })
    const none = await s.client.get('/api/token/')
    expect(none.status).toBe(401)
    expect(none.headers.get('www-authenticate')).toBe('Token')
    const invalid = await s.client.get('/api/token/', {
      headers: { authorization: 'Token nope', ...JSON_ACCEPT },
    })
    expect(invalid.status).toBe(401)
    expect(invalid.headers.get('www-authenticate')).toBe('Token')
    expect(await invalid.json()).toEqual({ detail: 'Invalid token.', code: 'authentication_failed' })
    const spaces = await s.client.get('/api/token/', {
      headers: { authorization: 'Token a b', ...JSON_ACCEPT },
    })
    expect((await spaces.json()).detail).toMatch(/should not contain spaces/)
    await User.objects.filter({ pk: ann.pk }).update({ isActive: false })
    const inactive = await s.client.get('/api/token/', {
      headers: { authorization: `Token ${token}`, ...JSON_ACCEPT },
    })
    expect((await inactive.json()).detail).toBe('User inactive or deleted.')
  })

  it('BasicAuthentication', async () => {
    const b64 = (v: string) => Buffer.from(v).toString('base64')
    const ok = await s.client.get('/api/basic/', { headers: { authorization: `Basic ${b64('ann:pw-ann')}` } })
    expect(await ok.json()).toEqual({ user: 'ann', token: 'no' })
    const bad = await s.client.get('/api/basic/', {
      headers: { authorization: `Basic ${b64('ann:no')}`, ...JSON_ACCEPT },
    })
    expect(bad.status).toBe(401)
    expect(bad.headers.get('www-authenticate')).toBe('Basic realm="api"')
    expect((await bad.json()).detail).toBe('Invalid username/password.')
    const garbage = await s.client.get('/api/basic/', {
      headers: { authorization: 'Basic %%%', ...JSON_ACCEPT },
    })
    expect((await garbage.json()).detail).toMatch(/base64/)
  })

  it('JWT: obtain pair, authenticate, refresh with rotation + blacklist, verify, blacklist', async () => {
    const bad = await s.client.post('/api/jwt/obtain/', { json: { username: 'ann', password: 'no' } })
    expect(bad.status).toBe(401)
    expect((await bad.json()).code).toBe('no_active_account')

    const pair = await (
      await s.client.post('/api/jwt/obtain/', { json: { username: 'ann', password: 'pw-ann' } })
    ).json()
    expect(Object.keys(pair).sort()).toEqual(['access', 'refresh'])
    expect(await OutstandingToken.objects.count()).toBe(1)

    const access = await AccessToken.fromString(pair.access)
    expect(access.payload).toMatchObject({ token_type: 'access', user_id: ann.pk })
    expect(access.payload.exp - access.payload.iat).toBe(300)

    const me = await s.client.get('/api/jwt/', { headers: { authorization: `Bearer ${pair.access}` } })
    expect(await me.json()).toEqual({ user: 'ann', token: 'yes' })

    // a refresh token is not an access token
    const wrongType = await s.client.get('/api/jwt/', {
      headers: { authorization: `Bearer ${pair.refresh}`, ...JSON_ACCEPT },
    })
    expect(wrongType.status).toBe(401)
    const body = await wrongType.json()
    expect(body.code).toBe('token_not_valid')
    expect(body.messages[0].message).toMatch(/wrong type/)
    expect(wrongType.headers.get('www-authenticate')).toBe('Bearer realm="api"')
    const malformed = await s.client.get('/api/jwt/', {
      headers: { authorization: 'Bearer a b', ...JSON_ACCEPT },
    })
    expect((await malformed.json()).code).toBe('bad_authorization_header')
    const other = await s.client.get('/api/jwt/', { headers: { authorization: 'Token abc' } })
    expect(other.status).toBe(401)

    // refresh with rotation: new pair, old refresh blacklisted
    const refreshed = await (
      await s.client.post('/api/jwt/refresh/', { json: { refresh: pair.refresh } })
    ).json()
    expect(refreshed.access).toBeTruthy()
    expect(refreshed.refresh).toBeTruthy()
    expect(refreshed.refresh).not.toBe(pair.refresh)
    expect(await BlacklistedToken.objects.count()).toBe(1)
    const reuse = await s.client.post('/api/jwt/refresh/', { json: { refresh: pair.refresh } })
    expect(reuse.status).toBe(401)
    expect((await reuse.json()).detail).toMatch(/blacklisted/)

    // verify
    expect((await s.client.post('/api/jwt/verify/', { json: { token: refreshed.access } })).status).toBe(200)
    expect((await s.client.post('/api/jwt/verify/', { json: { token: pair.refresh } })).status).toBe(401)
    expect((await s.client.post('/api/jwt/verify/', { json: { token: 'x.y.z' } })).status).toBe(401)
    const missing = await s.client.post('/api/jwt/verify/', { json: {} })
    expect(missing.status).toBe(400)

    // blacklist (logout)
    expect(
      (await s.client.post('/api/jwt/blacklist/', { json: { refresh: refreshed.refresh } })).status,
    ).toBe(200)
    expect((await s.client.post('/api/jwt/refresh/', { json: { refresh: refreshed.refresh } })).status).toBe(
      401,
    )

    // deactivated users can't use their tokens
    const fresh = await (
      await s.client.post('/api/jwt/obtain/', { json: { username: 'ann', password: 'pw-ann' } })
    ).json()
    await User.objects.filter({ pk: ann.pk }).update({ isActive: false })
    const inactive = await s.client.get('/api/jwt/', {
      headers: { authorization: `Bearer ${fresh.access}`, ...JSON_ACCEPT },
    })
    expect((await inactive.json()).code).toBe('user_inactive')
  })

  it('expired and tampered JWTs are rejected', async () => {
    const refresh = await RefreshToken.forUser(ann)
    const access = refresh.accessToken
    const token = await access.encode()
    const tampered = `${token.slice(0, -2)}xx`
    expect(
      (await s.client.get('/api/jwt/', { headers: { authorization: `Bearer ${tampered}` } })).status,
    ).toBe(401)
    const now = Date.now()
    vi.spyOn(Date, 'now').mockReturnValue(now + 301_000)
    try {
      const res = await s.client.get('/api/jwt/', {
        headers: { authorization: `Bearer ${token}`, ...JSON_ACCEPT },
      })
      expect(res.status).toBe(401)
      expect((await res.json()).messages[0].message).toMatch(/expired/)
    } finally {
      vi.restoreAllMocks()
    }
    // custom claims are copied from refresh to access tokens
    refresh.set('tenant', 't1')
    expect(refresh.accessToken.payload.tenant).toBe('t1')
    expect(refresh.accessToken.payload.token_type).toBe('access')
  })
})

describe('OpenAPI security schemes', () => {
  it('each authentication class declares a static securityScheme', () => {
    expect(SessionAuthentication.securityScheme).toEqual({
      name: 'cookieAuth',
      scheme: { type: 'apiKey', in: 'cookie', name: 'sessionid' },
    })
    expect(TokenAuthentication.securityScheme).toEqual({
      name: 'tokenAuth',
      scheme: {
        type: 'apiKey',
        in: 'header',
        name: 'Authorization',
        description: 'Token-based authentication with required prefix "Token"',
      },
    })
    expect(JWTAuthentication.securityScheme).toEqual({
      name: 'jwtAuth',
      scheme: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' },
    })
    expect(BasicAuthentication.securityScheme).toEqual({
      name: 'basicAuth',
      scheme: { type: 'http', scheme: 'basic' },
    })
  })

  it("@ghuri/rest's OpenAPI generator picks them up", async () => {
    const { APIView, AllowAny, generateSchema } = await import('@ghuri/rest')
    class MeView extends APIView {
      override authenticationClasses = [
        SessionAuthentication,
        TokenAuthentication,
        JWTAuthentication,
        BasicAuthentication,
      ]
      override permissionClasses = [AllowAny]
      async get() {
        return { ok: true }
      }
    }
    const doc = generateSchema([path('me/', MeView.asView())]) as any
    expect(Object.keys(doc.components.securitySchemes).sort()).toEqual([
      'basicAuth',
      'cookieAuth',
      'jwtAuth',
      'tokenAuth',
    ])
    expect(doc.components.securitySchemes.jwtAuth).toEqual(JWTAuthentication.securityScheme.scheme)
    expect(doc.paths['/me/'].get.security).toEqual([
      { cookieAuth: [] },
      { tokenAuth: [] },
      { jwtAuth: [] },
      { basicAuth: [] },
      {},
    ])
  })
})
