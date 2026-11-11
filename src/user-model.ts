import { apps, ImproperlyConfigured, LookupError, tryGetContext } from '@ghuri/core'
import { isModelClass } from '@ghuri/orm'
import { type AbstractBaseUser, User, type UserModelClass } from './models/auth'

export const DEFAULT_USER_MODEL = 'auth.User'

/** `AUTH_USER_MODEL` (default `'auth.User'`). */
export function getUserModelLabel(): string {
  return (tryGetContext()?.settings.AUTH_USER_MODEL as string | undefined) ?? DEFAULT_USER_MODEL
}

/** Is `auth.User` replaced by a custom user model? */
export function isUserModelSwapped(): boolean {
  return getUserModelLabel() !== DEFAULT_USER_MODEL
}

/**
 * The active user model (`AUTH_USER_MODEL`). Use it instead of importing `User` in reusable code.
 * Throws `ImproperlyConfigured` when the model isn't installed.
 */
export function getUserModel<U extends AbstractBaseUser = any>(): UserModelClass<U> {
  const label = getUserModelLabel()
  if (label === DEFAULT_USER_MODEL) return User as unknown as UserModelClass<U>
  let model: unknown
  try {
    model = apps.getModel(label)
  } catch (err) {
    if (err instanceof LookupError) {
      throw new ImproperlyConfigured(`AUTH_USER_MODEL refers to model '${label}' that has not been installed`)
    }
    throw new ImproperlyConfigured("AUTH_USER_MODEL must be of the form 'app_label.model_name'", {
      cause: err,
    })
  }
  if (!isModelClass(model)) throw new ImproperlyConfigured(`AUTH_USER_MODEL '${label}' is not a model.`)
  return model as unknown as UserModelClass<U>
}
