// AUTH_USER_MODEL support for the bundled migrations (Django's `swappable = 'AUTH_USER_MODEL'` and
// `swappable_dependency(settings.AUTH_USER_MODEL)`). The migration files are written for the default
// `auth.User`; when the user model is swapped, the app configs load adapted copies instead.
import {
  type FieldDeconstruction,
  Migration,
  migrationsFromModule,
  type Operation,
} from '@ghuri/orm/migrations'
import { DEFAULT_USER_MODEL, getUserModelLabel } from './user-model'

const DEFAULT_LABEL = DEFAULT_USER_MODEL.toLowerCase()

/** Operations as stored (fields normalized to `{ type, options }`). */
type FieldsOperation = { fields?: Record<string, FieldDeconstruction>; field?: FieldDeconstruction }

function isUserRef(field: FieldDeconstruction): boolean {
  const to = field.options?.to
  return typeof to === 'string' && to.toLowerCase() === DEFAULT_LABEL
}

function retarget(field: FieldDeconstruction, label: string): FieldDeconstruction {
  return isUserRef(field) ? { ...field, options: { ...field.options, to: label } } : field
}

function referencesApp(field: FieldDeconstruction, app: string): boolean {
  const { to, through } = field.options ?? {}
  return [to, through].some((v) => typeof v === 'string' && v.split('.')[0] === app)
}

function operationFields(op: Operation): FieldDeconstruction[] {
  const o = op as unknown as FieldsOperation
  return o.fields ? Object.values(o.fields) : o.field ? [o.field] : []
}

/** The operation with every `to: 'auth.User'` pointing at `label` (a shallow copy when changed). */
function retargetOperation(op: Operation, label: string): Operation {
  const o = op as unknown as FieldsOperation
  let patch: FieldsOperation | undefined
  if (o.fields && Object.values(o.fields).some(isUserRef))
    patch = { fields: Object.fromEntries(Object.entries(o.fields).map(([k, f]) => [k, retarget(f, label)])) }
  else if (o.field && isUserRef(o.field)) patch = { field: retarget(o.field, label) }
  return patch ? Object.assign(Object.create(Object.getPrototypeOf(op)), op, patch) : op
}

/** Operations of the `auth` app on the `User` model (skipped when it is swapped out). */
function touchesUserModel(op: Operation): boolean {
  const o = op as unknown as { modelName?: string; name?: string; oldName?: string }
  const model = o.modelName ?? o.oldName ?? o.name
  return typeof model === 'string' && model.toLowerCase() === 'user'
}

/**
 * The migrations module of a bundled app, adapted to `AUTH_USER_MODEL` (read from the current settings):
 * unchanged for `auth.User`; otherwise `auth`'s `User` operations are dropped, relations to `auth.User`
 * point at the custom model and depend on its app (`[app, '__first__']`) instead of `auth`.
 */
export function migrationsForUserModel(
  appLabel: string,
  mod: Record<string, unknown>,
  label: string = getUserModelLabel(),
): Record<string, unknown> {
  if (label.toLowerCase() === DEFAULT_LABEL) return mod
  const userApp = label.split('.')[0]
  const out: Record<string, Migration> = {}
  for (const [name, m] of migrationsFromModule(mod) ?? []) {
    let operations = m.operations
    if (appLabel === 'auth') operations = operations.filter((op) => !touchesUserModel(op))
    const pointsAtUser = operations.some((op) => retargetOperation(op, label) !== op)
    operations = operations.map((op) => retargetOperation(op, label))
    let dependencies = m.dependencies
    if (pointsAtUser && appLabel !== 'auth') {
      const fields = operations.flatMap(operationFields)
      // `auth` was only a dependency because of auth.User: keep it when other auth models are referenced.
      if (!fields.some((f) => referencesApp(f, 'auth')))
        dependencies = dependencies.filter((d) => d[0] !== 'auth')
      if (userApp !== appLabel && !dependencies.some((d) => d[0] === userApp))
        dependencies = [...dependencies, [userApp, '__first__'] as const]
    }
    const adapted = new Migration({
      dependencies,
      operations,
      replaces: m.replaces,
      initial: m.initial,
      atomic: m.atomic,
      runBefore: m.runBefore,
    })
    adapted.name = m.name || name
    out[adapted.name] = adapted
  }
  return { migrations: out }
}
