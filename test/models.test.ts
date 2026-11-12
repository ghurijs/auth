import { apps, runChecks } from '@ghuri/core'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import {
  AllowAllUsersModelBackend,
  authenticate,
  ContentType,
  checkPassword,
  createPermissions,
  Group,
  getUserModel,
  ModelBackend,
  PBKDF2PasswordHasher,
  Permission,
  User,
  userLoginFailed,
} from '../src/index'
import { setupAuthApp } from './helpers'

type Setup = Awaited<ReturnType<typeof setupAuthApp>>

describe.each(['sqlite', 'pglite'] as const)('models, permissions and backends (%s)', (using) => {
  let s: Setup
  beforeAll(async () => {
    s = await setupAuthApp({ using })
  }, 60_000)
  afterAll(async () => {
    await s?.db.teardown()
  })
  beforeEach(async () => {
    await s.flush()
  })

  it('uses Django table names and labels', () => {
    expect(User._meta.label).toBe('auth.User')
    expect(User._meta.dbTable).toBe('auth_user')
    expect(Group._meta.dbTable).toBe('auth_group')
    expect(Permission._meta.label).toBe('auth.Permission')
    expect(ContentType._meta.label).toBe('contenttypes.ContentType')
    expect(ContentType._meta.dbTable).toBe('django_content_type')
    expect(User._meta.getField('groups')).toBeTruthy()
    expect((User._meta.getField('groups') as any).m2mDbTable()).toBe('auth_user_groups')
    expect((User._meta.getField('userPermissions') as any).m2mDbTable()).toBe('auth_user_user_permissions')
    expect(User._meta.concreteFields.map((f) => f.column)).toEqual([
      'id',
      'password',
      'last_login',
      'is_superuser',
      'username',
      'first_name',
      'last_name',
      'email',
      'is_staff',
      'is_active',
      'date_joined',
    ])
    expect(getUserModel()).toBe(User)
    expect(apps.isInstalled('authtoken')).toBe(true)
  })

  it('createUser / createSuperuser / password helpers', async () => {
    const u = await User.objects.createUser('ann', 'Ann@EXAMPLE.com', 's3cret', { firstName: 'Ann' })
    expect(u.pk).toBeTruthy()
    expect(u.email).toBe('Ann@example.com')
    expect(u.isStaff).toBe(false)
    expect(u.isActive).toBe(true)
    expect(u.dateJoined).toBeInstanceOf(Date)
    expect(u.password.startsWith('pbkdf2_sha256$1000$')).toBe(true)
    expect(await u.checkPassword('s3cret')).toBe(true)
    expect(await u.checkPassword('nope')).toBe(false)
    expect(u.getFullName()).toBe('Ann')
    expect(String(u)).toBe('ann')
    expect(u.isAuthenticated).toBe(true)
    expect(u.isAnonymous).toBe(false)

    const obj = await User.objects.createUser({ username: 'bob', password: null })
    expect(obj.hasUsablePassword()).toBe(false)

    const admin = await User.objects.createSuperuser('admin', 'a@b.c', 'pw')
    expect(admin.isStaff && admin.isSuperuser).toBe(true)
    await expect(User.objects.createSuperuser('x', null, 'pw', { isStaff: false })).rejects.toThrow(
      /isStaff=true/,
    )
    await expect(User.objects.createUser('', null, 'pw')).rejects.toThrow(/must be set/)
    expect((await User.objects.getByNaturalKey('ann')).pk).toBe(u.pk)
    expect(User.normalizeUsername('ｕｓｅｒ')).toBe('user')
  })

  it('upgrades outdated password hashes on checkPassword', async () => {
    const u = await User.objects.createUser('old', null, null)
    u.password = await new PBKDF2PasswordHasher({ iterations: 10 }).encode('legacy', 'x'.repeat(22))
    await u.save()
    expect(await u.checkPassword('legacy')).toBe(true)
    const fresh = await User.objects.get({ pk: u.pk })
    expect(fresh.password.split('$')[1]).toBe('1000')
    expect(await checkPassword('legacy', fresh.password)).toBe(true)
  })

  it('createPermissions creates default + Meta permissions for every model, idempotently', async () => {
    // flush() already recreated them (postMigrate): start from empty tables to see what it creates
    await s.db.flush({ inhibitPostMigrate: true })
    const created = await createPermissions()
    expect(created).toBeGreaterThan(20)
    expect(await createPermissions()).toBe(0)
    const ct = await ContentType.objects.getForModel(User)
    expect(ct.appLabel).toBe('auth')
    expect(ct.model).toBe('user')
    expect(ct.modelClass()).toBe(User)
    expect(ct.name).toBe('user')
    expect(await ContentType.objects.getForModel(new User())).toBe(ct)
    expect((await ContentType.objects.getForId(ct.pk)).pk).toBe(ct.pk)
    const codenames = await Permission.objects
      .filter({ contentType: ct })
      .orderBy('codename')
      .valuesList('codename', { flat: true })
    expect(codenames).toEqual(['add_user', 'change_user', 'delete_user', 'view_user'])
    const p = await Permission.objects.getByNaturalKey('add_user', 'auth', 'user')
    expect(p.name).toBe('Can add user')
    expect(await ContentType.objects.filter({ appLabel: 'sessions', model: 'session' }).exists()).toBe(true)
  })

  it('ModelBackend: user, group and superuser permissions with per-instance cache', async () => {
    await createPermissions()
    const u = await User.objects.createUser('ann', null, 'pw')
    const addUser = await Permission.objects.getByNaturalKey('add_user', 'auth', 'user')
    const viewGroup = await Permission.objects.getByNaturalKey('view_group', 'auth', 'group')
    const editors = await Group.objects.create({ name: 'editors' })
    await editors.permissions.add(viewGroup)
    await u.userPermissions.add(addUser)
    await u.groups.add(editors)

    expect(await u.hasPerm('auth.add_user')).toBe(true)
    expect(await u.hasPerm('auth.view_group')).toBe(true)
    expect(await u.hasPerm('auth.delete_user')).toBe(false)
    expect(await u.hasPerms(['auth.add_user', 'auth.view_group'])).toBe(true)
    expect(await u.hasModulePerms('auth')).toBe(true)
    expect(await u.hasModulePerms('sessions')).toBe(false)
    expect([...(await u.getUserPermissions())]).toEqual(['auth.add_user'])
    expect([...(await u.getGroupPermissions())]).toEqual(['auth.view_group'])
    expect((await u.getAllPermissions()).size).toBe(2)
    expect(await u.hasPerm('auth.add_user', { some: 'object' })).toBe(false)

    // cached on the instance until cleared / reloaded
    await u.userPermissions.clear()
    expect(await u.hasPerm('auth.add_user')).toBe(true)
    u.clearPermCache()
    expect(await u.hasPerm('auth.add_user')).toBe(false)
    const reloaded = await User.objects.get({ pk: u.pk })
    expect(await reloaded.hasPerm('auth.view_group')).toBe(true)

    // inactive users have no permissions
    reloaded.isActive = false
    expect(await reloaded.hasPerm('auth.view_group')).toBe(false)

    const root = await User.objects.createSuperuser('root', null, 'pw')
    expect(await root.hasPerm('anything.at_all')).toBe(true)
    expect((await root.getAllPermissions()).has('auth.delete_user')).toBe(true)

    const holders = await User.objects
      .withPerm('auth.view_group')
      .orderBy('username')
      .valuesList('username', { flat: true })
    expect(holders).toEqual(['ann', 'root'])
    expect(await User.objects.withPerm('auth.view_group', { includeSuperusers: false }).count()).toBe(1)
    expect((await editors.userSet.all()).map((x: any) => x.username)).toEqual(['ann'])
  })

  it('authenticate() checks credentials, isActive and sends userLoginFailed', async () => {
    const u = await User.objects.createUser('ann', null, 'pw')
    const failures: unknown[] = []
    const rec = ({ credentials }: { credentials: unknown }) => {
      failures.push(credentials)
    }
    userLoginFailed.connect(rec)
    try {
      const ok = await authenticate(undefined, { username: 'ann', password: 'pw' })
      expect(ok?.pk).toBe(u.pk)
      expect(ok?.backend).toBe('ModelBackend')
      expect(await authenticate(undefined, { username: 'ann', password: 'bad' })).toBeNull()
      expect(await authenticate(undefined, { username: 'ghost', password: 'pw' })).toBeNull()
      expect(await authenticate(undefined, { username: 'ann' })).toBeNull()
      expect(failures).toHaveLength(3)
      expect(failures[0]).toEqual({ username: 'ann', password: '********************' })
      u.isActive = false
      await u.save()
      expect(await authenticate(undefined, { username: 'ann', password: 'pw' })).toBeNull()
      expect(
        await new AllowAllUsersModelBackend().authenticate(undefined, { username: 'ann', password: 'pw' }),
      ).toBeTruthy()
      expect(await new ModelBackend().getUser(u.pk)).toBeNull()
    } finally {
      userLoginFailed.disconnect(rec)
    }
  })

  it('validates usernames and runs system checks', async () => {
    const bad = new User({ username: 'no spaces!', password: 'x' })
    await expect(bad.fullClean()).rejects.toThrow(/valid username/)
    const ok = new User({ username: 'émile.o+1@x', password: 'x', email: 'A@B.COM' })
    await ok.fullClean({ exclude: ['password'] })
    expect(ok.email).toBe('A@b.com')
    const messages = await runChecks({ settings: s.ctx.settings })
    expect(messages.filter((m) => m.id?.startsWith('auth.'))).toEqual([])
  })
})

describe('D1 smoke test', () => {
  let s: Setup
  beforeAll(async () => {
    s = await setupAuthApp({ using: 'd1' })
  }, 60_000)
  afterAll(async () => {
    await s?.db.teardown()
  })

  it('users, groups, permissions and authenticate on D1', async () => {
    await createPermissions()
    const u = await User.objects.createUser('dee', 'd@example.com', 'pw')
    const g = await Group.objects.create({ name: 'g' })
    await g.permissions.add(await Permission.objects.getByNaturalKey('change_user', 'auth', 'user'))
    await u.groups.add(g)
    expect(await u.hasPerm('auth.change_user')).toBe(true)
    expect((await authenticate(undefined, { username: 'dee', password: 'pw' }))?.pk).toBe(u.pk)
  })
})
