// django.contrib.contenttypes: one row per installed model.
import { apps, tryGetContext } from '@ghuri/core'
import { type BaseModel, CharField, isModelClass, Manager, Model, type ModelClass } from '@ghuri/orm'

const caches = new WeakMap<object, Map<string, ContentType>>()
const fallbackCache = new Map<string, Map<string, ContentType>>()

/** Django's ContentTypeManager: cached lookups by model. */
export class ContentTypeManager extends Manager<ContentType> {
  /** Cache per database configuration object (a new test database starts with an empty cache). */
  private cacheFor(alias: string): Map<string, ContentType> {
    const config = (tryGetContext()?.settings.DATABASES as Record<string, object> | undefined)?.[alias]
    if (config) {
      let m = caches.get(config)
      if (!m) {
        m = new Map()
        caches.set(config, m)
      }
      return m
    }
    let m = fallbackCache.get(alias)
    if (!m) {
      m = new Map()
      fallbackCache.set(alias, m)
    }
    return m
  }

  private remember(ct: ContentType, alias: string): void {
    const cache = this.cacheFor(alias)
    cache.set(`${ct.appLabel}.${ct.model}`, ct)
    cache.set(`#${String(ct.pk)}`, ct)
  }

  /** The ContentType of a model class or instance (created if missing). Cached. */
  async getForModel(model: ModelClass | BaseModel, opts: { using?: string } = {}): Promise<ContentType> {
    const cls = (isModelClass(model) ? model : (model as BaseModel).constructor) as ModelClass
    const meta = cls._meta
    const alias = opts.using ?? 'default'
    const key = `${meta.appLabel}.${meta.modelName}`
    const cached = this.cacheFor(alias).get(key)
    if (cached) return cached
    const qs = opts.using ? this.using(opts.using) : this.getQueryset()
    let ct = await qs.filter({ appLabel: meta.appLabel, model: meta.modelName }).first()
    if (!ct) {
      ;[ct] = await qs.getOrCreate({ appLabel: meta.appLabel, model: meta.modelName })
    }
    this.remember(ct, alias)
    return ct
  }

  /** ContentTypes for several models: `Map<model, ContentType>`. */
  async getForModels(models: Array<ModelClass | BaseModel>, opts: { using?: string } = {}) {
    const out = new Map<ModelClass, ContentType>()
    for (const m of models) {
      const cls = (isModelClass(m) ? m : (m as BaseModel).constructor) as ModelClass
      out.set(cls, await this.getForModel(cls, opts))
    }
    return out
  }

  /** ContentType by id (cached). */
  async getForId(id: unknown, opts: { using?: string } = {}): Promise<ContentType> {
    const alias = opts.using ?? 'default'
    const cached = this.cacheFor(alias).get(`#${String(id)}`)
    if (cached) return cached
    const qs = opts.using ? this.using(opts.using) : this.getQueryset()
    const ct = await qs.get({ pk: id })
    this.remember(ct, alias)
    return ct
  }

  getByNaturalKey(appLabel: string, model: string): Promise<ContentType> {
    return this.get({ appLabel, model })
  }

  /**
   * Forget cached content types: of one database alias, or of every database when `using` is omitted.
   * `createPermissions` (run on `postMigrate`, also after `flush`) clears the cache of its database first.
   */
  clearCache(using?: string): void {
    if (using !== undefined) {
      this.cacheFor(using).clear()
      fallbackCache.get(using)?.clear()
      return
    }
    this.cacheFor('default').clear()
    for (const m of fallbackCache.values()) m.clear()
    const dbs = tryGetContext()?.settings.DATABASES as Record<string, object> | undefined
    for (const config of Object.values(dbs ?? {})) caches.get(config)?.clear()
  }
}

/** One row per model: `(appLabel, model)`. Table `django_content_type`, like Django. */
export class ContentType extends Model({
  appLabel: new CharField({ maxLength: 100 }),
  model: new CharField({ maxLength: 100, verboseName: 'python model class name' }),
}) {
  static Meta = {
    dbTable: 'django_content_type',
    uniqueTogether: [['appLabel', 'model']],
    verboseName: 'content type',
    verboseNamePlural: 'content types',
  }
  static objects = new ContentTypeManager()

  /** The model class, or null if it is not installed. */
  modelClass(): ModelClass | null {
    try {
      const m = apps.getModel(this.appLabel, this.model)
      return isModelClass(m) ? m : null
    } catch {
      return null
    }
  }

  /** Verbose name of the model (or the stored model name if the model is gone). */
  get name(): string {
    return this.modelClass()?._meta.verboseName ?? this.model
  }

  get appLabeledName(): string {
    const m = this.modelClass()
    if (!m) return this.model
    const app = apps.isInstalled(this.appLabel) ? apps.getAppConfig(this.appLabel).displayName : this.appLabel
    return `${app} | ${m._meta.verboseName}`
  }

  /** `getObjectForThisType({ pk: 1 })`. */
  getObjectForThisType(lookup: Record<string, unknown>): Promise<BaseModel> {
    const m = this.modelClass()
    if (!m) throw new TypeError(`Model ${this.appLabel}.${this.model} is not installed.`)
    return m._baseManager.get(lookup)
  }

  getAllObjectsForThisType(filter: Record<string, unknown> = {}) {
    const m = this.modelClass()
    if (!m) throw new TypeError(`Model ${this.appLabel}.${this.model} is not installed.`)
    return m._baseManager.filter(filter)
  }

  naturalKey(): [string, string] {
    return [this.appLabel, this.model]
  }

  override toString(): string {
    return this.appLabeledName
  }
}
