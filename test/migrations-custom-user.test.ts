// AUTH_USER_MODEL swapped: in its own file because relations to the user model resolve once per process.
import { apps, createApp, defineSettings } from '@ghuri/core'
import { MigrationLoader, makeMigrations } from '@ghuri/orm/migrations'
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import {
  AuthConfig,
  AuthTokenConfig,
  ContentTypesConfig,
  Permission,
  SessionsConfig,
  Token,
  TokenBlacklistConfig,
} from '../src/index'
import { AccountsConfig, EmailUser } from './accounts/app'
import { SECRET, setupAuthApp } from './helpers'

const INSTALLED_APPS = [
  ContentTypesConfig,
  AuthConfig,
  SessionsConfig,
  AuthTokenConfig,
  TokenBlacklistConfig,
  AccountsConfig,
]

describe('bundled migrations with AUTH_USER_MODEL swapped', () => {
  beforeAll(async () => {
    const settings = {
      SECRET_KEY: SECRET,
      AUTH_USER_MODEL: 'accounts.EmailUser',
      INSTALLED_APPS,
      ROOT_URLCONF: [],
    }
    await createApp(defineSettings(() => settings)).setup({})
  })

  it('drops auth.User and points relations at the custom model', async () => {
    const loader = await MigrationLoader.load({ connection: null })
    const deps = Object.fromEntries([...loader.migrations.values()].map((m) => [String(m), m.dependencies]))
    expect(deps).toMatchObject({
      'authtoken.0001_initial': [['accounts', '__first__']],
      'token_blacklist.0001_initial': [['accounts', '__first__']],
    })
    const state = loader.projectState()
    expect(state.models.has('auth.user')).toBe(false)
    expect(state.models.has('auth.group')).toBe(true)
    const tokenUser = state.models.get('authtoken.token')?.fields.get('user')
    expect(tokenUser?.options.to).toBe('accounts.EmailUser')
    expect(apps.getAppConfig('authtoken').path).toBeUndefined()
  })

  it('makemigrations --check: no changes', async () => {
    const result = await makeMigrations({ check: true, interactive: false })
    expect(result.migrations.map((m) => m.source)).toEqual([])
  })
})

describe('migrate from zero with AUTH_USER_MODEL swapped (sqlite)', () => {
  let s: Awaited<ReturnType<typeof setupAuthApp>>
  beforeAll(async () => {
    s = await setupAuthApp({
      settings: {
        AUTH_USER_MODEL: 'accounts.EmailUser',
        INSTALLED_APPS: [
          ContentTypesConfig,
          AuthConfig,
          AuthTokenConfig,
          TokenBlacklistConfig,
          AccountsConfig,
        ],
      },
    })
  })
  afterAll(async () => {
    await s?.db.teardown()
  })

  it('creates no auth_user table and relates tokens to the custom model', async () => {
    const tables = await s.db.connection.execute(
      "SELECT name FROM sqlite_master WHERE type = 'table' AND name IN ('auth_user', 'accounts_emailuser')",
    )
    expect(JSON.stringify(tables)).not.toContain('auth_user')
    expect(JSON.stringify(tables)).toContain('accounts_emailuser')
    const u = await EmailUser.objects.createUser({ email: 'x@example.com', password: 'pw' })
    const t = await Token.objects.create({ user: u })
    expect(((await (await Token.objects.get({ key: t.key })).user) as any).email).toBe('x@example.com')
    expect(await Permission.objects.filter({ codename: 'add_emailuser' }).exists()).toBe(true)
  })
})
