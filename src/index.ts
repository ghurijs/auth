// @ghuri/auth — users, groups, permissions, sessions, tokens, JWT. See ARCHITECTURE.md §6.
// Workers-safe: WebCrypto only, no Node-only imports.
import './settings'
import './testing'

export { AnonymousUser, anonymousUser, getUser, type RequestUser, setUser } from '@ghuri/core'
export {
  AuthConfig,
  AuthTokenConfig,
  authApps,
  ContentTypesConfig,
  SessionsConfig,
  TokenBlacklistConfig,
} from './apps'
export {
  authenticate,
  BACKEND_SESSION_KEY,
  cleanseCredentials,
  getSession,
  getUserFromSession,
  HASH_SESSION_KEY,
  login,
  logout,
  REDIRECT_FIELD_NAME,
  SESSION_KEY,
  updateSessionAuthHash,
} from './auth'
export {
  AllowAllUsersModelBackend,
  AllowAllUsersRemoteUserBackend,
  BaseBackend,
  type Credentials,
  getBackends,
  loadBackend,
  ModelBackend,
  RemoteUserBackend,
} from './backends'
export { checkUserModel } from './checks'
export {
  ChangePasswordCommand,
  ClearSessionsCommand,
  CreateSuperuserCommand,
  CreateTokenCommand,
  FlushExpiredTokensCommand,
} from './commands'
export {
  AccessMixin,
  type AccessOptions,
  denyAccess,
  LoginRequiredMixin,
  loginRequired,
  PermissionRequiredMixin,
  permissionRequired,
  redirectToLogin,
  staffMemberRequired,
  UserPassesTestMixin,
  type UserTest,
  userPassesTest,
} from './decorators'
export {
  AuthenticationFailed,
  AuthHttpError,
  CreateError,
  ExpiredTokenError,
  InvalidToken,
  NotAuthenticated,
  TokenError,
  UpdateError,
} from './errors'
export {
  BasePasswordHasher,
  checkPassword,
  DEFAULT_PASSWORD_HASHERS,
  type DecodedHash,
  getHasher,
  getHashers,
  identifyHasher,
  isPasswordUsable,
  makePassword,
  makeUnusablePassword,
  maskHash,
  PBKDF2PasswordHasher,
  PBKDF2SHA1PasswordHasher,
  pbkdf2,
  ScryptPasswordHasher,
  UNUSABLE_PASSWORD_PREFIX,
  UNUSABLE_PASSWORD_SUFFIX_LENGTH,
  verifyPassword,
  WORKERS_PBKDF2_MAX_ITERATIONS,
} from './hashers'
export {
  AccessToken,
  blacklistInstalled,
  type JWTAlgorithm,
  type JWTPayload,
  type JWTSettings,
  JWTToken,
  jwtSettings,
  RefreshToken,
  tokenPairForUser,
  UntypedToken,
} from './jwt'
export {
  AuthenticationMiddleware,
  PersistentRemoteUserMiddleware,
  RemoteUserMiddleware,
  SessionMiddleware,
} from './middleware'
export {
  AbstractBaseUser,
  AbstractUser,
  asciiUsernameValidator,
  BaseUserManager,
  Group,
  GroupManager,
  normalizeEmail,
  Permission,
  PermissionManager,
  PermissionsMixin,
  permissionsMixinFields,
  User,
  UserManager,
  type UserModelClass,
  type UserModelStatics,
  unicodeUsernameValidator,
} from './models/auth'
export { ContentType, ContentTypeManager } from './models/contenttypes'
export { Session, SessionManager } from './models/sessions'
export { BlacklistedToken, generateTokenKey, OutstandingToken, Token } from './models/tokens'
export {
  CommonPasswordValidator,
  getDefaultPasswordValidators,
  getPasswordValidators,
  MinimumLengthValidator,
  NumericPasswordValidator,
  type PasswordValidator,
  type PasswordValidatorConfig,
  passwordChanged,
  passwordValidatorsHelpTexts,
  UserAttributeSimilarityValidator,
  validatePassword,
} from './password-validation'
export { type CreatePermissionsOptions, createContentTypes, createPermissions } from './permissions'
export {
  CacheSessionStore,
  DatabaseSessionStore,
  getSessionStoreClass,
  type KVNamespaceLike,
  KVSessionStore,
  SessionBase,
  type SessionConfig,
  type SessionData,
  type SessionEngine,
  type SessionStoreClass,
  SignedCookieSessionStore,
  sessionConfig,
} from './sessions/index'
export { userLoggedIn, userLoggedOut, userLoginFailed } from './signals'
export {
  asciiJson,
  BadSignature,
  dumps,
  JSONSerializer,
  loads,
  type Serializer,
  SignatureExpired,
  Signer,
  type SignerOptions,
  signing,
  TimestampSigner,
} from './signing'
export { migrationsForUserModel } from './swappable'
export { defaultTokenGenerator, PasswordResetTokenGenerator } from './tokens'
export { DEFAULT_USER_MODEL, getUserModel, getUserModelLabel, isUserModelSwapped } from './user-model'
export {
  b64urlDecode,
  b64urlEncode,
  constantTimeCompare,
  getRandomString,
  saltedHmac,
  urlsafeBase64Decode,
  urlsafeBase64Encode,
} from './utils/crypto'
export {
  authUrls,
  isSafeRedirect,
  LoginView,
  LogoutView,
  PasswordChangeView,
  PasswordResetConfirmView,
  type PasswordResetInfo,
  PasswordResetView,
  readData,
  WhoAmIView,
} from './views'
