// Default permissions (Django's create_permissions / create_contenttypes post-migrate handlers).
import { type AppConfig, apps } from '@ghuri/core'
import { isAbstractModel, isModelClass, type ModelClass } from '@ghuri/orm'
import { Permission } from './models/auth'
import { ContentType } from './models/contenttypes'

export interface CreatePermissionsOptions {
  /** Only this app (config or label); default: every installed app. */
  appConfig?: AppConfig | string
  /** Database alias (default `'default'`). */
  using?: string
  /** 0 = silent, 2 = print created permissions. */
  verbosity?: number
  stdout?: (msg: string) => void
}

function modelsFor(appConfig?: AppConfig | string): ModelClass[] {
  const label = typeof appConfig === 'string' ? appConfig : appConfig?.appLabel
  return (apps.getModels(label) as unknown[]).filter(
    (m): m is ModelClass => isModelClass(m) && !isAbstractModel(m) && !m._meta.autoCreated,
  )
}

/** Make sure every installed model has a ContentType row. Returns the content types by model. */
export async function createContentTypes(
  opts: CreatePermissionsOptions = {},
): Promise<Map<ModelClass, ContentType>> {
  const out = new Map<ModelClass, ContentType>()
  for (const model of modelsFor(opts.appConfig)) {
    out.set(model, await ContentType.objects.getForModel(model, { using: opts.using }))
  }
  return out
}

/**
 * Create the default `add/change/delete/view` permissions (`Meta.defaultPermissions`) plus
 * `Meta.permissions` for every installed model. Idempotent; returns the number of permissions created.
 * Runs automatically after `migrate` (ORM `postMigrate` signal) and is exported for tests and scripts.
 */
export async function createPermissions(opts: CreatePermissionsOptions = {}): Promise<number> {
  if (!apps.isInstalled('auth') || !apps.isInstalled('contenttypes')) return 0
  const cts = await createContentTypes(opts)
  if (!cts.size) return 0
  const wanted: Array<{ ct: ContentType; codename: string; name: string }> = []
  for (const [model, ct] of cts) {
    const meta = model._meta
    for (const action of meta.defaultPermissions) {
      wanted.push({ ct, codename: `${action}_${meta.modelName}`, name: `Can ${action} ${meta.verboseName}` })
    }
    for (const [codename, name] of meta.permissions) wanted.push({ ct, codename, name })
  }
  const qs = opts.using ? Permission.objects.using(opts.using) : Permission.objects.all()
  const ctIds = [...new Set([...cts.values()].map((ct) => ct.pk))]
  const existing = new Set(
    (
      (await qs.filter({ contentType__in: ctIds }).orderBy().valuesList('contentType', 'codename')) as Array<
        [unknown, string]
      >
    ).map(([ct, code]) => `${String(ct)}:${code}`),
  )
  const seen = new Set<string>()
  const toCreate: Permission[] = []
  for (const w of wanted) {
    const key = `${String(w.ct.pk)}:${w.codename}`
    if (existing.has(key) || seen.has(key)) continue
    seen.add(key)
    toCreate.push(new Permission({ name: w.name, contentType: w.ct, codename: w.codename }))
  }
  if (toCreate.length) {
    await (opts.using ? Permission.objects.using(opts.using) : Permission.objects.all()).bulkCreate(toCreate)
    if ((opts.verbosity ?? 1) >= 2) {
      for (const p of toCreate) opts.stdout?.(`Adding permission '${p.codename}'`)
    }
  }
  return toCreate.length
}
