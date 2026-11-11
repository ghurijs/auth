import { type CheckFunction, type CheckMessage, checks } from '@ghuri/core'
import { getUserModel } from './user-model'

/** System checks for the user model (Django's auth.E00x). */
export const checkUserModel: CheckFunction = () => {
  const out: CheckMessage[] = []
  let User: ReturnType<typeof getUserModel>
  try {
    User = getUserModel()
  } catch (err) {
    return [checks.error((err as Error).message, { id: 'auth.E001' })]
  }
  const meta = User._meta
  if (!Array.isArray(User.REQUIRED_FIELDS)) {
    out.push(checks.error("'REQUIRED_FIELDS' must be an array.", { id: 'auth.E001', obj: User }))
  } else if (User.REQUIRED_FIELDS.includes(User.USERNAME_FIELD)) {
    out.push(
      checks.error(
        `The field named as the 'USERNAME_FIELD' for a custom user model must not be included in 'REQUIRED_FIELDS'.`,
        { id: 'auth.E002', obj: User },
      ),
    )
  }
  const field = meta.getForwardField(User.USERNAME_FIELD)
  if (!field) {
    out.push(
      checks.error(`'${meta.objectName}.USERNAME_FIELD' ('${User.USERNAME_FIELD}') is not a field.`, {
        id: 'auth.E003',
        obj: User,
      }),
    )
  } else if (!field.unique) {
    out.push(
      checks.error(
        `'${meta.objectName}.${User.USERNAME_FIELD}' must be unique because it is named as the 'USERNAME_FIELD'.`,
        {
          id: 'auth.E003',
          obj: User,
        },
      ),
    )
  }
  return out
}
