import { bufferIO, CommandError, type CommandIO, callCommand, commandRegistry } from '@ghuri/core'
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest'
import {
  CommonPasswordValidator,
  MinimumLengthValidator,
  OutstandingToken,
  Session,
  Token,
  User,
  UserAttributeSimilarityValidator,
} from '../src/index'
import { setupAuthApp } from './helpers'

/** IO whose prompt answers from a script and records the questions. */
function scriptedIO(answers: string[]): CommandIO & { out: string[]; err: string[]; questions: string[] } {
  const io = bufferIO() as CommandIO & { out: string[]; err: string[]; questions: string[] }
  io.questions = []
  io.prompt = async (q) => {
    io.questions.push(q)
    return answers.shift() as string
  }
  return io
}

describe('management commands', () => {
  let s: Awaited<ReturnType<typeof setupAuthApp>>
  beforeAll(async () => {
    s = await setupAuthApp({
      settings: {
        AUTH_PASSWORD_VALIDATORS: [
          { NAME: MinimumLengthValidator, OPTIONS: { minLength: 8 } },
          UserAttributeSimilarityValidator,
          CommonPasswordValidator,
        ],
      },
    })
  })
  afterAll(async () => {
    await s?.db.teardown()
  })
  beforeEach(async () => {
    await s.flush()
  })

  it('are registered from the app configs', () => {
    for (const name of [
      'createsuperuser',
      'changepassword',
      'clearsessions',
      'drf_create_token',
      'flushexpiredtokens',
    ]) {
      expect(commandRegistry.get(name), name).toBeTruthy()
    }
  })

  it('createsuperuser (interactive): re-prompts on taken names, mismatches and weak passwords', async () => {
    await User.objects.createUser('taken', null, 'x')
    const io = scriptedIO([
      'taken', // already taken
      'admin',
      'admin@EXAMPLE.com',
      'secret-one',
      'secret-two', // mismatch
      'short',
      'short', // too short → bypass? no
      'n',
      'admin123',
      'admin123', // too similar → bypass? yes
      'y',
    ])
    await callCommand('createsuperuser', {}, io)
    expect(io.questions.slice(0, 3)).toEqual(['Username: ', 'Username: ', 'Email address: '])
    expect(io.err).toContain('Error: That username is already taken.')
    expect(io.err).toContain("Error: Your passwords didn't match.")
    expect(io.err.join('\n')).toMatch(/too short/)
    expect(io.err.join('\n')).toMatch(/too similar to the username/)
    expect(io.out).toEqual(['Superuser created successfully.'])
    const admin = await User.objects.get({ username: 'admin' })
    expect(admin.isSuperuser && admin.isStaff).toBe(true)
    expect(admin.email).toBe('admin@example.com')
    expect(await admin.checkPassword('admin123')).toBe(true)
  })

  it('createsuperuser rejects blank passwords and invalid usernames', async () => {
    const io = scriptedIO(['bad name!', 'okname', '', '', '   ', '   ', 'Str0ng-and-l0ng', 'Str0ng-and-l0ng'])
    await callCommand('createsuperuser', { email: 'ok@example.com' }, io)
    expect(io.err[0]).toMatch(/Enter a valid username/)
    expect(io.err.filter((e) => e === "Error: Blank passwords aren't allowed.")).toHaveLength(2)
    expect(await User.objects.filter({ username: 'okname', email: 'ok@example.com' }).exists()).toBe(true)
  })

  it('createsuperuser --no-input uses options and GHURI_SUPERUSER_PASSWORD', async () => {
    process.env.GHURI_SUPERUSER_PASSWORD = 'from-env-pw'
    try {
      await callCommand('createsuperuser', { noInput: true, username: 'ci', email: 'ci@example.com' })
    } finally {
      delete process.env.GHURI_SUPERUSER_PASSWORD
    }
    const ci = await User.objects.get({ username: 'ci' })
    expect(await ci.checkPassword('from-env-pw')).toBe(true)
    await callCommand('createsuperuser', { 'no-input': true, username: 'pw', email: '', password: 'opt-pw' })
    expect(await (await User.objects.get({ username: 'pw' })).checkPassword('opt-pw')).toBe(true)
    await callCommand('createsuperuser', { input: false, username: 'nopw' })
    expect((await User.objects.get({ username: 'nopw' })).hasUsablePassword()).toBe(false)
    await expect(callCommand('createsuperuser', { noInput: true })).rejects.toBeInstanceOf(CommandError)
    await expect(callCommand('createsuperuser', { noInput: true, username: 'ci' })).rejects.toThrow(
      /already taken/,
    )
  })

  it('changepassword', async () => {
    await User.objects.createUser('ann', null, 'old-password')
    const io = scriptedIO(['new-pass-1', 'new-pass-2', 'abc', 'abc', 'Better-Pass-9', 'Better-Pass-9'])
    await callCommand('changepassword', { username: 'ann' }, io)
    expect(io.out).toContain('Passwords do not match. Please try again.')
    expect(io.err.join('\n')).toMatch(/too short/)
    expect(io.out.at(-1)).toBe("Password changed successfully for user 'ann'")
    expect(await (await User.objects.get({ username: 'ann' })).checkPassword('Better-Pass-9')).toBe(true)

    const tooMany = scriptedIO(['a', 'b', 'c', 'd', 'e', 'f'])
    await expect(callCommand('changepassword', { username: 'ann' }, tooMany)).rejects.toThrow(
      /after 3 attempts/,
    )
    await expect(callCommand('changepassword', { username: 'ghost', password: 'x' })).rejects.toThrow(
      /does not exist/,
    )
    await callCommand('changepassword', { username: 'ann', password: 'Scripted-Pass-1' })
    expect(await (await User.objects.get({ username: 'ann' })).checkPassword('Scripted-Pass-1')).toBe(true)
  })

  it('clearsessions, drf_create_token and flushexpiredtokens', async () => {
    await Session.objects.create({
      sessionKey: 'expired-session-1',
      sessionData: 'x',
      expireDate: new Date(Date.now() - 1000),
    })
    await Session.objects.create({
      sessionKey: 'live-session-123',
      sessionData: 'x',
      expireDate: new Date(Date.now() + 60_000),
    })
    await callCommand('clearsessions')
    expect(await Session.objects.valuesList('sessionKey', { flat: true })).toEqual(['live-session-123'])

    const ann = await User.objects.createUser('ann', null, 'pw')
    const io = bufferIO()
    await callCommand('drf_create_token', { username: 'ann' }, io)
    const key = (await Token.objects.get({ user: ann.pk })).key
    expect(io.out[0]).toBe(`Generated token ${key} for user ann`)
    await callCommand('drf_create_token', { username: 'ann', reset: true })
    expect((await Token.objects.get({ user: ann.pk })).key).not.toBe(key)

    await OutstandingToken.objects.create({ jti: 'a', token: 't', expiresAt: new Date(Date.now() - 1000) })
    await OutstandingToken.objects.create({ jti: 'b', token: 't', expiresAt: new Date(Date.now() + 60_000) })
    await callCommand('flushexpiredtokens')
    expect(await OutstandingToken.objects.valuesList('jti', { flat: true })).toEqual(['b'])
  })
})
