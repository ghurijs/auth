// A project app with a custom user model (AUTH_USER_MODEL = 'accounts.EmailUser') and its migrations,
// like a real project: a swapped-in user model must live in an app with migrations (as in Django).
import { AppConfig } from '@ghuri/core'
import { BooleanField, CharField, EmailField, Model } from '@ghuri/orm'
import { PermissionsMixin, type UserManager } from '../../src/index'
import * as migrations from './migrations/index'

/** A custom user model logging in with its email address. */
export class EmailUser extends Model(
  {
    email: new EmailField({ unique: true, verboseName: 'email address' }),
    fullName: new CharField({ maxLength: 100, blank: true, verboseName: 'full name' }),
    isStaff: new BooleanField({ default: false }),
    isActive: new BooleanField({ default: true }),
  },
  { extends: PermissionsMixin },
) {
  static USERNAME_FIELD = 'email'
  static EMAIL_FIELD = 'email'
  static REQUIRED_FIELDS = ['fullName']
  declare static objects: UserManager<EmailUser>
}

export class AccountsConfig extends AppConfig {
  name = 'accounts'
  override path = import.meta.dirname
  override models = { EmailUser }
  override migrations = migrations
}
