import { apps, createApp, defineSettings } from '@ghuri/core'
import {
  MigrationLoader,
  makeMigrations,
  migrate,
  setMigrationDiskLoader,
  setMigrationFileSystem,
  showMigrations,
} from '@ghuri/orm/migrations'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { ContentType, Permission, Token, User } from '../src/index'
import { ALL_APPS, SECRET, setupAuthApp } from './helpers'

const LABELS = ['contenttypes', 'auth', 'sessions', 'authtoken', 'token_blacklist']

async function setupApps(settings: Record<string, unknown> = {}) {
  const app = createApp(
    defineSettings(() => ({ SECRET_KEY: SECRET, INSTALLED_APPS: ALL_APPS, ROOT_URLCONF: [], ...settings })),
  )
  await app.setup({})
}

function dependencies(loader: MigrationLoader): Record<string, unknown> {
  return Object.fromEntries([...loader.migrations.values()].map((m) => [String(m), m.dependencies]))
}

describe('bundled migrations', () => {
  beforeAll(() => setupApps())

  it('every app has an initial migration with the right dependencies', async () => {
    const loader = await MigrationLoader.load({ connection: null, source: 'modules' })
    expect(dependencies(loader)).toEqual({
      'contenttypes.0001_initial': [],
      'auth.0001_initial': [['contenttypes', '0001_initial']],
      'sessions.0001_initial': [],
      'authtoken.0001_initial': [['auth', '0001_initial']],
      'token_blacklist.0001_initial': [['auth', '0001_initial']],
    })
    for (const label of LABELS) expect(loader.migratedApps.has(label)).toBe(true)
    expect(loader.migrations.get('auth.0001_initial')?.initial).toBe(true)
  })

  it('path points at src/<app> when running from source', () => {
    for (const label of LABELS)
      expect(apps.getAppConfig(label).path?.replace(/\\/g, '/')).toMatch(new RegExp(`/src/${label}$`))
  })

  it('makemigrations --check: the models match the migrations', async () => {
    const result = await makeMigrations({ check: true, interactive: false })
    expect(result.migrations).toEqual([])
    expect(result.exitCode).toBe(0)
  })

  it('makemigrations --check reading src/<app>/migrations from disk (the CLI)', async () => {
    const { loadMigrationsFromDisk } = await import('@ghuri/orm/commands')
    try {
      const loader = await MigrationLoader.load({ connection: null, source: 'disk' })
      expect(Object.keys(dependencies(loader)).sort()).toEqual(LABELS.map((l) => `${l}.0001_initial`).sort())
      expect([...((await loadMigrationsFromDisk(apps.getAppConfig('auth'))) ?? []).keys()]).toEqual([
        '0001_initial',
      ])
      const result = await makeMigrations({ check: true, interactive: false })
      expect(result.exitCode).toBe(0)
    } finally {
      setMigrationDiskLoader(undefined)
      setMigrationFileSystem(undefined)
    }
  })
})

describe.each(['sqlite', 'pglite', 'd1'] as const)('migrate from zero (%s)', (using) => {
  let s: Awaited<ReturnType<typeof setupAuthApp>>
  beforeAll(async () => {
    s = await setupAuthApp({ using })
  })
  afterAll(async () => {
    await s?.db.teardown()
  })

  it('applies every migration', async () => {
    const status = (await showMigrations({ appLabels: LABELS })).map((m) => [m.app, m.name, m.applied])
    expect(status).toEqual(
      expect.arrayContaining(LABELS.map((l) => [l, '0001_initial', true] as [string, string, boolean])),
    )
    expect(status).toHaveLength(LABELS.length)
  })

  it('creates the content types and default permissions (postMigrate)', async () => {
    const codenames = (await Permission.objects.valuesList('codename', { flat: true })) as string[]
    for (const c of [
      'add_user',
      'change_group',
      'delete_permission',
      'view_contenttype',
      'view_session',
      'add_token',
      'view_outstandingtoken',
      'view_blacklistedtoken',
    ])
      expect(codenames).toContain(c)
    expect(await ContentType.objects.filter({ appLabel: 'sessions', model: 'session' }).exists()).toBe(true)
  })

  it('the tables work, and an app can be unapplied and reapplied', async () => {
    const u = await User.objects.createUser('ann', 'ann@example.com', 'pw')
    const t = await Token.objects.create({ user: u })
    expect((await Token.objects.get({ user: u })).key).toBe(t.key)

    await migrate({ appLabel: 'authtoken', target: 'zero' })
    let status = await showMigrations({ appLabels: ['authtoken'] })
    expect(status.map((m) => m.applied)).toEqual([false])
    await expect(Token.objects.count()).rejects.toThrow()

    await migrate()
    status = await showMigrations({ appLabels: ['authtoken'] })
    expect(status.map((m) => m.applied)).toEqual([true])
    expect(await Token.objects.count()).toBe(0)
    expect(await Permission.objects.filter({ codename: 'add_token' }).count()).toBe(1)
  })
})
