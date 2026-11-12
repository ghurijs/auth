import { apps, callCommand, include, path } from '@ghuri/core'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import {
  AuthConfig,
  AuthTokenConfig,
  authenticate,
  authUrls,
  ContentTypesConfig,
  createPermissions,
  Group,
  getUserModel,
  isUserModelSwapped,
  Permission,
  SessionsConfig,
  Token,
  User,
} from '../src/index'
import { AccountsConfig, EmailUser } from './accounts/app'
import { setupAuthApp } from './helpers'

describe('custom user model (AUTH_USER_MODEL = accounts.EmailUser)', () => {
  let s: Awaited<ReturnType<typeof setupAuthApp>>
  beforeAll(async () => {
    s = await setupAuthApp({
      urls: [path('accounts/', include(authUrls))],
      settings: {
        AUTH_USER_MODEL: 'accounts.EmailUser',
        INSTALLED_APPS: [ContentTypesConfig, AuthConfig, SessionsConfig, AuthTokenConfig, AccountsConfig],
      },
    })
  })
  afterAll(async () => {
    await s?.db.teardown()
  })
  beforeEach(async () => {
    await s.flush()
  })

  it('swaps auth.User out', () => {
    expect(isUserModelSwapped()).toBe(true)
    expect(getUserModel()).toBe(EmailUser)
    expect(apps.getModels('auth')).not.toContain(User)
    expect(apps.getModels('auth')).toContain(Group)
    expect(EmailUser._meta.dbTable).toBe('accounts_emailuser')
    expect((EmailUser._meta.getField('groups') as any).m2mDbTable()).toBe('accounts_emailuser_groups')
    expect((Token._meta.getField('user') as any).relatedModel).toBe(EmailUser)
  })

  it('UserManager works with USERNAME_FIELD = email', async () => {
    const a = await EmailUser.objects.createUser('ann@EXAMPLE.com', undefined, 'pw', { fullName: 'Ann' })
    expect(a.email).toBe('ann@example.com')
    const b = await EmailUser.objects.createSuperuser({ email: 'root@example.com', password: 'pw' })
    expect(b.isSuperuser && b.isStaff).toBe(true)
    expect((await EmailUser.objects.getByNaturalKey('ann@example.com')).pk).toBe(a.pk)
    expect((await authenticate(undefined, { email: 'ann@example.com', password: 'pw' }))?.pk).toBe(a.pk)
    expect((await authenticate(undefined, { username: 'ann@example.com', password: 'pw' }))?.pk).toBe(a.pk)
    expect(await authenticate(undefined, { email: 'ann@example.com', password: 'no' })).toBeNull()
  })

  it('permissions, groups and tokens work for the custom model', async () => {
    await createPermissions()
    expect(await Permission.objects.filter({ codename: 'add_emailuser' }).exists()).toBe(true)
    expect(await Permission.objects.filter({ codename: 'add_user' }).exists()).toBe(false)
    const u = await EmailUser.objects.createUser({ email: 'g@example.com', password: 'pw' })
    const g = await Group.objects.create({ name: 'staff' })
    await g.permissions.add(
      await Permission.objects.getByNaturalKey('view_emailuser', 'accounts', 'emailuser'),
    )
    await u.groups.add(g)
    expect(await u.hasPerm('accounts.view_emailuser')).toBe(true)
    const t = await Token.objects.create({ user: u })
    expect(t.key).toMatch(/^[0-9a-f]{40}$/)
    expect(((await (await Token.objects.get({ key: t.key })).user) as any).email).toBe('g@example.com')
  })

  it('createsuperuser --no-input with the custom fields', async () => {
    await callCommand('createsuperuser', {
      noInput: true,
      email: 'cli@example.com',
      fullName: 'Cli',
      password: 'pw',
    })
    const u = await EmailUser.objects.get({ email: 'cli@example.com' })
    expect(u.fullName).toBe('Cli')
    expect(u.isSuperuser).toBe(true)
  })

  it('JSON login with the email field', async () => {
    await EmailUser.objects.createUser({ email: 'web@example.com', password: 'pw' })
    const res = await s.client.post('/accounts/login/', {
      json: { email: 'web@example.com', password: 'pw' },
    })
    expect(res.status).toBe(200)
    expect(await res.json()).toMatchObject({ user: { email: 'web@example.com' } })
  })
})
