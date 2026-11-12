// JWTs for a second model (a shop's customers) next to AUTH_USER_MODEL: `JWTToken.userModel()`,
// `RefreshToken.accessTokenClass` and the views' `tokenClass`. The two token kinds never authenticate each other.
import { csrfExempt, json, path } from '@ghuri/core'
import { BooleanField, EmailField, Model, registerModels } from '@ghuri/orm'
import type { Context } from 'hono'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import { AbstractBaseUser, AccessToken, OutstandingToken, RefreshToken, User } from '../src/index'
import { type BaseAuthentication, JWTAuthentication, TokenBlacklistView, TokenRefreshView } from '../src/rest'
import { setupAuthApp } from './helpers'

class Customer extends Model(
  {
    email: new EmailField({ unique: true }),
    isActive: new BooleanField({ default: true }),
  },
  { extends: AbstractBaseUser },
) {
  static Meta = { appLabel: 'shoptest' }
  static override USERNAME_FIELD = 'email'
}
registerModels('shoptest', { Customer })

class CustomerAccessToken extends AccessToken {
  static override tokenType = 'customer_access'
  static override userModel() {
    return Customer as any
  }
}
class CustomerRefreshToken extends RefreshToken {
  static override tokenType = 'customer_refresh'
  static override accessTokenClass = CustomerAccessToken
  static override userModel() {
    return Customer as any
  }
}
class CustomerJWTAuthentication extends JWTAuthentication {
  override tokenClasses = [CustomerAccessToken]
}
class CustomerTokenRefreshView extends TokenRefreshView {
  override tokenClass = CustomerRefreshToken
}
class CustomerTokenBlacklistView extends TokenBlacklistView {
  override tokenClass = CustomerRefreshToken
}

function whoami(Cls: new () => BaseAuthentication) {
  return csrfExempt(async (c: Context) => {
    try {
      const result = await new Cls().authenticate(c)
      if (!result) return json(c, { who: null }, 401)
      const [user] = result as [any, unknown]
      return json(c, { who: user.email ?? user.username, model: user.constructor.name })
    } catch (err: any) {
      return json(c, { error: err.message }, err.status ?? 401)
    }
  })
}

const urls = [
  path('me/', whoami(JWTAuthentication)),
  path('customer/me/', whoami(CustomerJWTAuthentication)),
  path('customer/refresh/', CustomerTokenRefreshView.asView()),
  path('customer/logout/', CustomerTokenBlacklistView.asView()),
  path('refresh/', TokenRefreshView.asView()),
]

describe('JWTs for a custom user model', () => {
  let s: Awaited<ReturnType<typeof setupAuthApp>>
  let ann: User
  let cus: Customer
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
    cus = new Customer({ email: 'cus@example.com' })
    await cus.setPassword('pw-cus')
    await cus.save()
    // Same primary key on both sides: the token type, not the id, decides which model a token belongs to.
    expect(String(cus.pk)).toBe(String(ann.pk))
  })

  const bearer = (t: string) => ({ headers: { authorization: `Bearer ${t}` } })

  it('issues and authenticates customer tokens', async () => {
    const refresh = await CustomerRefreshToken.forUser(cus as any)
    const access = refresh.accessToken
    expect(access).toBeInstanceOf(CustomerAccessToken)
    expect(access.payload.token_type).toBe('customer_access')
    const res = await s.client.get('/customer/me/', bearer(await access.encode()))
    expect(await res.json()).toEqual({ who: 'cus@example.com', model: 'Customer' })
  })

  it('never accepts one kind of token for the other', async () => {
    const customerAccess = await (await CustomerRefreshToken.forUser(cus as any)).accessToken.encode()
    const userAccess = await (await RefreshToken.forUser(ann)).accessToken.encode()
    expect((await s.client.get('/me/', bearer(customerAccess))).status).toBe(401)
    expect((await s.client.get('/customer/me/', bearer(userAccess))).status).toBe(401)
    expect(await (await s.client.get('/me/', bearer(userAccess))).json()).toEqual({
      who: 'ann@example.com',
      model: 'User',
    })
  })

  it('refreshes, rotates and blacklists customer refresh tokens without touching AUTH_USER_MODEL', async () => {
    const raw = await (await CustomerRefreshToken.forUser(cus as any)).encode()
    // The default refresh view rejects a customer refresh token.
    expect((await s.client.post('/refresh/', { json: { refresh: raw } })).status).toBe(401)

    const res = await s.client.post('/customer/refresh/', { json: { refresh: raw } })
    expect(res.status).toBe(200)
    const body = await res.json()
    const access = await CustomerAccessToken.fromString(body.access)
    expect(access.payload.token_type).toBe('customer_access')
    // Rotation blacklisted the old token; its outstanding record has no AUTH_USER_MODEL user.
    const outstanding = await OutstandingToken.objects.all().fetch()
    expect(outstanding.length).toBeGreaterThan(0)
    expect(outstanding.every((o) => o.userId === null)).toBe(true)
    expect((await s.client.post('/customer/refresh/', { json: { refresh: raw } })).status).toBe(401)

    expect((await s.client.post('/customer/logout/', { json: { refresh: body.refresh } })).status).toBe(200)
    expect((await s.client.post('/customer/refresh/', { json: { refresh: body.refresh } })).status).toBe(401)
  })
})
