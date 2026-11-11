// Management commands: createsuperuser, changepassword, clearsessions, drf_create_token, flushexpiredtokens.
import {
  type ArgumentParser,
  BaseCommand,
  CommandError,
  type CommandIO,
  tryGetContext,
  ValidationError,
} from '@ghuri/core'
import { OutstandingToken, Token } from './models/tokens'
import { validatePassword } from './password-validation'
import { getSessionStoreClass } from './sessions/index'
import { getUserModel } from './user-model'

function envValue(name: string): string | undefined {
  const fromCtx = tryGetContext()?.env?.[name]
  if (typeof fromCtx === 'string') return fromCtx
  const proc = (globalThis as any).process
  const v = proc?.env?.[name]
  return typeof v === 'string' ? v : undefined
}

function isNonInteractive(args: Record<string, unknown>, io: CommandIO): boolean {
  return (
    args.noInput === true ||
    args['no-input'] === true ||
    args.noinput === true ||
    args.input === false ||
    args.interactive === false ||
    typeof io.prompt !== 'function'
  )
}

function messages(err: unknown): string[] {
  if (err instanceof ValidationError) return err.messages
  return [(err as Error)?.message ?? String(err)]
}

function capfirst(s: string): string {
  return s ? s.charAt(0).toUpperCase() + s.slice(1) : s
}

function envName(field: string): string {
  return `GHURI_SUPERUSER_${field.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toUpperCase()}`
}

async function ask(io: CommandIO, question: string, opts?: { password?: boolean }): Promise<string> {
  const answer = await io.prompt!(question, opts)
  if (answer === undefined || answer === null) throw new CommandError('Operation cancelled.')
  return answer
}

async function askYesNo(io: CommandIO, question: string): Promise<boolean> {
  if (typeof io.confirm === 'function') return io.confirm(question, { default: false })
  return /^y(es)?$/i.test((await ask(io, `${question} [y/N]: `)).trim())
}

/**
 * `ghuri createsuperuser` — interactive (prompts with password confirmation and validators) or
 * `--no-input` with `--username`, `--email` (each `REQUIRED_FIELDS` entry) and the password from
 * `--password` or `GHURI_SUPERUSER_PASSWORD` (`GHURI_SUPERUSER_<FIELD>` env vars also work).
 */
export class CreateSuperuserCommand extends BaseCommand {
  static override help = 'Used to create a superuser.'

  addArguments(parser: ArgumentParser): void {
    let fields = ['username', 'email']
    try {
      const User = getUserModel()
      fields = [User.USERNAME_FIELD, ...User.REQUIRED_FIELDS]
    } catch {}
    for (const f of new Set(fields))
      parser.option(`--${f} <value>`, { help: `Specifies the ${f} for the superuser.` })
    parser.option('--password <value>', {
      help: 'Password (non-interactive mode); prefer GHURI_SUPERUSER_PASSWORD.',
    })
    parser.option('--no-input', { help: 'Do NOT prompt for input of any kind.' })
    parser.option('--database <alias>', { help: 'Database alias (default "default").' })
  }

  async handle(args: Record<string, unknown>, io: CommandIO): Promise<void> {
    const User = getUserModel()
    const meta = User._meta
    const usernameField = meta.getForwardField(User.USERNAME_FIELD)
    if (!usernameField) throw new CommandError(`USERNAME_FIELD '${User.USERNAME_FIELD}' is not a field.`)
    const database = (args.database as string | undefined) ?? 'default'
    const manager = database === 'default' ? User.objects : (User.objects.using(database) as any)
    const data: Record<string, unknown> = {}
    const fieldNames = [User.USERNAME_FIELD, ...User.REQUIRED_FIELDS]
    const probe = new User()

    const clean = (name: string, raw: unknown): unknown => {
      const field = meta.getForwardField(name)
      if (!field) return raw
      return field.clean(raw, probe)
    }
    const taken = async (value: unknown) => manager.filter({ [User.USERNAME_FIELD]: value }).exists()

    let password: string | null = null
    if (isNonInteractive(args, io)) {
      for (const name of fieldNames) {
        const raw = (args[name] as string | undefined) ?? envValue(envName(name))
        if (raw === undefined || raw === '') {
          if (name === User.USERNAME_FIELD || !meta.getForwardField(name)?.blank) {
            throw new CommandError(`You must use --${name} with --no-input.`)
          }
          continue
        }
        try {
          data[name] = clean(name, raw)
        } catch (err) {
          throw new CommandError(messages(err).join('; '))
        }
      }
      if (await taken(data[User.USERNAME_FIELD])) {
        throw new CommandError(`Error: That ${usernameField.verboseName} is already taken.`)
      }
      password = (args.password as string | undefined) ?? envValue('GHURI_SUPERUSER_PASSWORD') ?? null
    } else {
      // username
      for (;;) {
        const given = args[User.USERNAME_FIELD] as string | undefined
        const raw = given ?? (await ask(io, `${capfirst(usernameField.verboseName)}: `))
        try {
          if (!raw) throw new ValidationError('This field cannot be blank.')
          const value = clean(User.USERNAME_FIELD, raw)
          if (await taken(value))
            throw new ValidationError(`That ${usernameField.verboseName} is already taken.`)
          data[User.USERNAME_FIELD] = value
          break
        } catch (err) {
          io.stderr(`Error: ${messages(err).join('; ')}`)
          if (given !== undefined) delete args[User.USERNAME_FIELD]
        }
      }
      for (const name of User.REQUIRED_FIELDS) {
        const field = meta.getForwardField(name)
        for (;;) {
          const given = args[name] as string | undefined
          const raw = given ?? (await ask(io, `${capfirst(field?.verboseName ?? name)}: `))
          try {
            if (!raw && !field?.blank) throw new ValidationError('This field cannot be blank.')
            data[name] = raw ? clean(name, raw) : raw
            break
          } catch (err) {
            io.stderr(`Error: ${messages(err).join('; ')}`)
            if (given !== undefined) delete args[name]
          }
        }
      }
      // password
      for (;;) {
        const p1 = await ask(io, 'Password: ', { password: true })
        const p2 = await ask(io, 'Password (again): ', { password: true })
        if (p1 !== p2) {
          io.stderr("Error: Your passwords didn't match.")
          continue
        }
        if (p1.trim() === '') {
          io.stderr("Error: Blank passwords aren't allowed.")
          continue
        }
        try {
          await validatePassword(p1, new User(data))
        } catch (err) {
          if (!(err instanceof ValidationError)) throw err
          io.stderr(err.messages.join('\n'))
          if (!(await askYesNo(io, 'Bypass password validation and create user anyway?'))) continue
        }
        password = p1
        break
      }
    }

    const { [User.USERNAME_FIELD]: username, ...extra } = data
    await manager.createSuperuser({ [User.USERNAME_FIELD]: username, ...extra, password })
    io.stdout(io.style.success('Superuser created successfully.'))
  }
}

/** `ghuri changepassword [username]` — interactive, or `--password` for scripts. */
export class ChangePasswordCommand extends BaseCommand {
  static override help = "Change a user's password."
  static maxTries = 3

  addArguments(parser: ArgumentParser): void {
    parser.argument('username', { help: 'Username to change password for.' })
    parser.option('--password <value>', { help: 'New password (non-interactive).' })
    parser.option('--database <alias>', { help: 'Database alias (default "default").' })
  }

  async handle(args: Record<string, unknown>, io: CommandIO): Promise<void> {
    const User = getUserModel()
    const database = (args.database as string | undefined) ?? 'default'
    const manager = database === 'default' ? User._defaultManager : User._defaultManager.using(database)
    const username = (args.username as string | undefined) ?? envValue('USER') ?? envValue('USERNAME')
    if (!username) throw new CommandError('Specify the username.')
    let user: any
    try {
      user = await manager.get({ [User.USERNAME_FIELD]: username })
    } catch (err) {
      if (err instanceof User.DoesNotExist) throw new CommandError(`user '${username}' does not exist`)
      throw err
    }
    io.stdout(`Changing password for user '${username}'`)
    let password = args.password as string | undefined
    if (password !== undefined) {
      await validatePassword(password, user).catch((err) => {
        throw new CommandError(messages(err).join('\n'))
      })
    } else {
      if (typeof io.prompt !== 'function')
        throw new CommandError('No password given and no interactive prompt available.')
      const max = (this.constructor as typeof ChangePasswordCommand).maxTries
      let tries = 0
      while (password === undefined) {
        if (tries >= max) {
          throw new CommandError(`Aborting password change for user '${username}' after ${tries} attempts`)
        }
        tries++
        const p1 = await ask(io, 'Password: ', { password: true })
        const p2 = await ask(io, 'Password (again): ', { password: true })
        if (p1 !== p2) {
          io.stdout('Passwords do not match. Please try again.')
          continue
        }
        try {
          await validatePassword(p2, user)
        } catch (err) {
          io.stderr(messages(err).join('\n'))
          continue
        }
        password = p1
      }
    }
    await user.setPassword(password)
    await user.save()
    io.stdout(io.style.success(`Password changed successfully for user '${username}'`))
  }
}

/** `ghuri clearsessions` — delete expired sessions (db engine; KV/cache expire by themselves). */
export class ClearSessionsCommand extends BaseCommand {
  static override help = 'Can be run as a cronjob or directly to clean out expired sessions.'

  async handle(_args: Record<string, unknown>, io: CommandIO): Promise<void> {
    const Store = getSessionStoreClass(tryGetContext()?.settings.SESSION_ENGINE)
    await Store.clearExpired()
    io.stdout('Expired sessions cleared.')
  }
}

/** `ghuri drf_create_token <username> [--reset]` — create (or reset) a user's API token. */
export class CreateTokenCommand extends BaseCommand {
  static override help = 'Create DRF Token for a given user'

  addArguments(parser: ArgumentParser): void {
    parser.argument('username', { required: true })
    parser.option('-r, --reset', { help: 'Reset existing User token and create a new one' })
  }

  async handle(args: Record<string, unknown>, io: CommandIO): Promise<void> {
    const User = getUserModel()
    const username = args.username as string
    let user: any
    try {
      user = await User._defaultManager.get({ [User.USERNAME_FIELD]: username })
    } catch (err) {
      if (err instanceof User.DoesNotExist)
        throw new CommandError(`Cannot create the Token: user ${username} does not exist`)
      throw err
    }
    if (args.reset) await Token.objects.filter({ user: user.pk }).delete()
    const [token] = await Token.objects.getOrCreate({ user })
    io.stdout(`Generated token ${token.key} for user ${username}`)
  }
}

/** `ghuri flushexpiredtokens` — delete expired outstanding JWT refresh tokens (token_blacklist app). */
export class FlushExpiredTokensCommand extends BaseCommand {
  static override help = 'Flushes any expired tokens in the outstanding token list'

  async handle(_args: Record<string, unknown>, io: CommandIO): Promise<void> {
    const [n] = await OutstandingToken.objects.filter({ expiresAt__lte: new Date() }).delete()
    io.stdout(`Deleted ${n} expired token(s).`)
  }
}
