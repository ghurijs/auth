// DRF authtoken (`authtoken.Token`) and simplejwt's token blacklist (`token_blacklist.*`).
import {
  CASCADE,
  CharField,
  DateTimeField,
  ForeignKey,
  type Manager,
  Model,
  type ModelClass,
  OneToOneField,
  SET_NULL,
  TextField,
} from '@ghuri/orm'
import { getUserModel } from '../user-model'
import { bytesToHex, randomBytes } from '../utils/crypto'

/** Lazy relation target for the (swappable) user model. */
const userModel = () => getUserModel() as unknown as ModelClass

/** 40 hex characters (DRF's `Token.generate_key`). */
export function generateTokenKey(): string {
  return bytesToHex(randomBytes(20))
}

/** DRF-style API token: one per user, sent as `Authorization: Token <key>`. Table `authtoken_token`. */
export class Token extends Model({
  key: new CharField({ maxLength: 40, primaryKey: true, default: generateTokenKey, verboseName: 'Key' }),
  user: new OneToOneField(userModel, { onDelete: CASCADE, relatedName: 'authToken', verboseName: 'User' }),
  created: new DateTimeField({ autoNowAdd: true, verboseName: 'Created' }),
}) {
  static Meta = { dbTable: 'authtoken_token', verboseName: 'Token', verboseNamePlural: 'Tokens' }
  declare static objects: Manager<Token>

  static generateKey(): string {
    return generateTokenKey()
  }

  override toString(): string {
    return this.key
  }
}

/** Every refresh token issued (when the `token_blacklist` app is installed). */
export class OutstandingToken extends Model({
  user: new ForeignKey(userModel, {
    onDelete: SET_NULL,
    null: true,
    blank: true,
    relatedName: 'outstandingTokens',
  }),
  jti: new CharField({ maxLength: 255, unique: true }),
  token: new TextField(),
  createdAt: new DateTimeField({ null: true, blank: true }),
  expiresAt: new DateTimeField(),
}) {
  static Meta = {
    dbTable: 'token_blacklist_outstandingtoken',
    ordering: ['user'],
    verboseName: 'outstanding token',
    verboseNamePlural: 'outstanding tokens',
  }
  declare static objects: Manager<OutstandingToken>

  override toString(): string {
    return `Token for ${String(this.userId)} (${this.jti})`
  }
}

/** Refresh tokens that may no longer be used. */
export class BlacklistedToken extends Model({
  token: new OneToOneField(() => OutstandingToken, { onDelete: CASCADE, relatedName: 'blacklistedtoken' }),
  blacklistedAt: new DateTimeField({ autoNowAdd: true }),
}) {
  static Meta = {
    dbTable: 'token_blacklist_blacklistedtoken',
    verboseName: 'blacklisted token',
    verboseNamePlural: 'blacklisted tokens',
  }
  declare static objects: Manager<BlacklistedToken>

  override toString(): string {
    return `Blacklisted token ${String(this.tokenId)}`
  }
}
