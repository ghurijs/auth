// Regression: permissions must exist again after a test database flush (postMigrate after flush).
import { afterAll, beforeAll, describe, expect, it } from 'vitest'
import { ContentType, Permission, User } from '../src/index'
import { setupAuthApp } from './helpers'

type Setup = Awaited<ReturnType<typeof setupAuthApp>>

describe.each(['sqlite', 'pglite'] as const)('permissions after flush (%s)', (using) => {
  let s: Setup
  beforeAll(async () => {
    s = await setupAuthApp({ using })
  }, 60_000)
  afterAll(async () => {
    await s?.db.teardown()
  })

  it('setupTestDatabase creates the default permissions', async () => {
    expect(await Permission.objects.count()).toBeGreaterThan(20)
  })

  it('db.flush() recreates content types and permissions (postMigrate), without a stale ContentType cache', async () => {
    const before = await ContentType.objects.getForModel(User)
    await s.db.flush()
    const p = await Permission.objects.getByNaturalKey('add_user', 'auth', 'user')
    expect(p.name).toBe('Can add user')
    const ct = await ContentType.objects.getForModel(User)
    expect(await ContentType.objects.filter({ pk: ct.pk }).exists()).toBe(true)
    expect(ct).not.toBe(before)
    expect(await User.objects.count()).toBe(0)
  })
})
