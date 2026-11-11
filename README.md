# @ghuri/auth

Django's `django.contrib.auth`, `contenttypes` and `sessions` — plus DRF's `authtoken` and
`djangorestframework-simplejwt` — for [Ghuri](https://github.com/ghurijs/ghuri), the Django-style
TypeScript framework for Cloudflare Workers (and Node).

Users, groups and permissions, Django-compatible password hashing on WebCrypto, sessions in D1/Postgres,
Workers KV, a cache or a signed cookie, login/logout, permission decorators, API tokens, JWT, REST
authentication classes and the `createsuperuser` command.

> Status: alpha (`0.1.0-alpha.0`). APIs may change.

```bash
npm install @ghuri/auth@next
```

## Contents

- [Setup](#setup)
- [Users](#users)
- [Custom user model](#custom-user-model)
- [Passwords](#passwords)
- [Sessions](#sessions)
- [Login and logout](#login-and-logout)
- [Permissions and groups](#permissions-and-groups)
- [Protecting views](#protecting-views)
- [Auth views](#auth-views)
- [API tokens and JWT](#api-tokens-and-jwt)
- [REST authentication (`@ghuri/auth/rest`)](#rest-authentication-ghuriauthrest)
- [Signing](#signing)
- [Commands](#commands)
- [Testing](#testing)
- [Settings reference](#settings-reference)
- [Moving from Django](#moving-from-django)
- [Differences from Django](#differences-from-django)

## Setup

```ts
// src/settings.ts
import { CommonMiddleware, CsrfMiddleware, SecurityMiddleware, defineSettings } from '@ghuri/core'
import { d1 } from '@ghuri/orm'
import {
  AuthConfig, AuthenticationMiddleware, AuthTokenConfig, ContentTypesConfig, SessionMiddleware, SessionsConfig,
} from '@ghuri/auth'
import { urlpatterns } from './urls'

export default defineSettings((env) => ({
  SECRET_KEY: env.SECRET_KEY,
  INSTALLED_APPS: [ContentTypesConfig, AuthConfig, SessionsConfig, AuthTokenConfig /* , your apps */],
  MIDDLEWARE: [SecurityMiddleware, SessionMiddleware, CommonMiddleware, CsrfMiddleware, AuthenticationMiddleware],
  ROOT_URLCONF: urlpatterns,
  DATABASES: { default: d1('DB') },
}))
```

| App config | Label | Models (table) |
|---|---|---|
| `ContentTypesConfig` | `contenttypes` | `ContentType` (`django_content_type`) |
| `AuthConfig` | `auth` | `User` (`auth_user`), `Group`, `Permission` |
| `SessionsConfig` | `sessions` | `Session` (`django_session`) — needed for `SESSION_ENGINE: 'db'` |
| `AuthTokenConfig` | `authtoken` | `Token` (`authtoken_token`) — DRF-style API tokens |
| `TokenBlacklistConfig` | `token_blacklist` | `OutstandingToken`, `BlacklistedToken` — JWT refresh revocation |

`authApps` is `[ContentTypesConfig, AuthConfig, SessionsConfig]` for spreading. `auth` requires `contenttypes`.
Table and column names are Django's, so an existing Django database (or a `dumpdata` of one) fits as is.

Then `ghuri makemigrations && ghuri migrate` and `ghuri createsuperuser`. After `migrate`, the default
permissions are created automatically.

## Users

```ts
import { User } from '@ghuri/auth'

const ann = await User.objects.createUser('ann', 'ann@example.com', 's3cret!', { firstName: 'Ann' })
await User.objects.createUser({ username: 'bob', email: 'bob@example.com', password: 'pw' })  // object form
await User.objects.createSuperuser('admin', 'admin@example.com', 's3cret!')

await ann.checkPassword('s3cret!')  // true
await ann.setPassword('n3w-pass'); await ann.save()
ann.setUnusablePassword(); ann.hasUsablePassword()
ann.getFullName(); ann.getUsername(); ann.isAuthenticated // true
await User.objects.getByNaturalKey('ann')
```

`User` has Django's fields in camelCase: `username`, `password`, `email`, `firstName`, `lastName`, `isStaff`,
`isActive`, `isSuperuser`, `lastLogin`, `dateJoined`, M2M `groups` and `userPermissions`. Usernames are
NFKC-normalized and validated with `unicodeUsernameValidator`; email domains are lower-cased.

In reusable code don't import `User` — call `getUserModel()` (it honors `AUTH_USER_MODEL`).

## Custom user model

```ts
// src/accounts/models.ts
import { BooleanField, CharField, EmailField, Model } from '@ghuri/orm'
import { PermissionsMixin, type UserManager } from '@ghuri/auth'

export class Account extends Model(
  {
    email: new EmailField({ unique: true, verboseName: 'email address' }),
    displayName: new CharField({ maxLength: 100, blank: true }),
    isStaff: new BooleanField({ default: false }),
    isActive: new BooleanField({ default: true }),
  },
  { extends: PermissionsMixin },
) {
  static USERNAME_FIELD = 'email'
  static EMAIL_FIELD = 'email'
  static REQUIRED_FIELDS = ['displayName']
  declare static objects: UserManager<Account>
}
```

```ts
// settings
AUTH_USER_MODEL: 'accounts.Account',
INSTALLED_APPS: [ContentTypesConfig, AuthConfig, SessionsConfig, AccountsConfig],
```

- `AbstractBaseUser` — `password`, `lastLogin`, password helpers, permission checks delegated to the backends.
- `PermissionsMixin` — `AbstractBaseUser` + `isSuperuser`, `groups`, `userPermissions` (Ghuri model
  inheritance is linear, so the mixin already contains the base user). `permissionsMixinFields()` gives the
  bare field set.
- `AbstractUser` — everything `User` has; extend it to add fields to the default user.

The built-in `UserManager` works for any `USERNAME_FIELD`: `Account.objects.createUser('a@b.c', undefined, 'pw')`
or `createUser({ email, password, ... })`. Subclass `BaseUserManager` for custom creation logic. When the model
is swapped, `auth.User` isn't registered (no `auth_user` table) and relations such as `Token.user` point at
your model. Decide on the user model before the first migration, as in Django.

## Passwords

Hashes use Django's formats, computed with WebCrypto (Workers-safe):

| Hasher | Format | Notes |
|---|---|---|
| `PBKDF2PasswordHasher` (default) | `pbkdf2_sha256$<iter>$<salt>$<hash>` | 100,000 iterations by default |
| `PBKDF2SHA1PasswordHasher` | `pbkdf2_sha1$…` | legacy Django installs |
| `ScryptPasswordHasher` | `scrypt$<n>$<salt>$<r>$<p>$<hash>` | pure-JS scrypt (no WebCrypto primitive) |

```ts
import { checkPassword, makePassword, PBKDF2PasswordHasher, ScryptPasswordHasher } from '@ghuri/auth'

PASSWORD_HASHERS: [new PBKDF2PasswordHasher({ iterations: 600_000 }), ScryptPasswordHasher]  // classes or instances

const encoded = await makePassword('s3cret')                 // preferred (first) hasher
await checkPassword('s3cret', encoded, async (pw) => { /* re-hash: outdated algorithm/params */ })
await makePassword(null)                                      // unusable password ('!' + 40 chars)
```

**Iterations and Workers CPU.** Django uses 1,000,000 PBKDF2 iterations. Production Workers' WebCrypto has
refused more than 100,000 and the free plan allows ~10 ms of CPU per request, so Ghuri defaults to
**100,000** (~25–50 ms of CPU: fine on the paid plan, may hit the free plan's limit — lower it there, or raise
it on Node where there is no such limit). When WebCrypto refuses a count, Ghuri falls back to a pure-JS
PBKDF2 (1,000,000 iterations ≈ 0.7 s of CPU — paid plan only), so Django hashes always verify, and
`user.checkPassword()` transparently re-hashes with the configured parameters on the next successful login,
exactly like Django's hasher upgrades.

Validation — `AUTH_PASSWORD_VALIDATORS` (empty by default, like Django):

```ts
AUTH_PASSWORD_VALIDATORS: [
  { NAME: UserAttributeSimilarityValidator },
  { NAME: MinimumLengthValidator, OPTIONS: { minLength: 9 } },
  { NAME: CommonPasswordValidator },          // compact built-in list; OPTIONS: { passwords: [...] } for yours
  { NAME: NumericPasswordValidator },
],
// validatePassword(password, user?) throws one ValidationError with every message
```

## Sessions

`SessionMiddleware` puts the session on `c.get('session')`. The API is async because data loads lazily:

```ts
const session = c.get('session')                  // or getSession(c)
await session.set('cart', [1, 2])
await session.get('cart', [])                     // with a default
await session.has('cart'); await session.delete('cart'); await session.pop('x')
await session.setExpiry(0)                        // expire at browser close (seconds | Date | null)
await session.cycleKey(); await session.flush()
```

| `SESSION_ENGINE` | Storage | |
|---|---|---|
| `'db'` (default) | `django_session` table (`SessionsConfig`) | strongly consistent, works everywhere |
| `'kv'` | Workers KV binding `SESSION_KV_BINDING` (default `SESSIONS`) | fast edge reads; eventually consistent (~60 s) |
| `'cache'` | a core cache (`SESSION_CACHE_ALIAS`) | sessions are lost when the cache evicts |
| `'signedCookie'` | the cookie itself, signed with `SECRET_KEY` | no storage; readable by the client, ~4 KB, can't be revoked early |
| a `SessionBase` subclass | your store | |

Django's settings apply: `SESSION_COOKIE_NAME` (`sessionid`), `SESSION_COOKIE_AGE` (2 weeks),
`SESSION_COOKIE_DOMAIN`, `SESSION_COOKIE_PATH`, `SESSION_COOKIE_SECURE`, `SESSION_COOKIE_HTTPONLY` (true),
`SESSION_COOKIE_SAMESITE` (`'Lax'`), `SESSION_SAVE_EVERY_REQUEST`, `SESSION_EXPIRE_AT_BROWSER_CLOSE`. Session
payloads use Django's signed, compressed JSON encoding. `ghuri clearsessions` deletes expired database sessions.

## Login and logout

```ts
import { authenticate, login, logout } from '@ghuri/auth'

const user = await authenticate(c, { username, password })   // null when invalid (sends userLoginFailed)
if (user) await login(c, user)                               // rotates the session key + CSRF token
await logout(c)                                              // flushes the session
await updateSessionAuthHash(c, user)                         // keep this session after a password change
```

`AuthenticationMiddleware` sets the request user (`getUser(c)` / `c.get('user')`, an `AnonymousUser` when not
logged in). Requests without a session cookie never touch the database; with one, the session and the user are
loaded before the view runs (a TS getter can't lazily await, so "lazy" here means "only when there is a
session"). Sessions are bound to the password hash: changing a password logs out every other session.

`AUTHENTICATION_BACKENDS` (default `[ModelBackend]`): `ModelBackend` (username or `USERNAME_FIELD` + password,
rejects `isActive = false`), `AllowAllUsersModelBackend`, `RemoteUserBackend` (with `RemoteUserMiddleware` /
`PersistentRemoteUserMiddleware`, header `REMOTE_USER_HEADER`), or your own `BaseBackend` subclass. Give custom
backends a `static backendName` (the name stored in the session).

Signals: `userLoggedIn` (updates `lastLogin`; disconnect uid `ghuri.auth.updateLastLogin` to opt out),
`userLoggedOut`, `userLoginFailed` (credentials with sensitive values masked).

## Permissions and groups

```ts
await user.hasPerm('blog.add_post')            // active superusers always true
await user.hasPerms(['blog.add_post', 'blog.change_post'])
await user.hasModulePerms('blog')
await user.getAllPermissions()                 // Set<'app.codename'>; cached on the instance
user.clearPermCache()

const editors = await Group.objects.create({ name: 'editors' })
await editors.permissions.add(await Permission.objects.getByNaturalKey('change_post', 'blog', 'post'))
await user.groups.add(editors)
await User.objects.withPerm('blog.change_post')    // users having it (incl. superusers)
await ContentType.objects.getForModel(Post)        // cached
```

`add_`, `change_`, `delete_` and `view_` permissions (`Meta.defaultPermissions`) plus `Meta.permissions`
(`[['publish_post', 'Can publish posts']]`) are created for every installed model by `createPermissions()`.
It runs after `ghuri migrate` (through the ORM's `postMigrate` signal) and can be called from tests or scripts.

## Protecting views

```ts
import { loginRequired, permissionRequired, staffMemberRequired, userPassesTest } from '@ghuri/auth'

path('dashboard/', loginRequired(dashboard))
path('posts/new/', permissionRequired('blog.add_post')(newPost))
path('reports/', userPassesTest((u) => u.isStaff)(reports))
path('ops/', staffMemberRequired(ops))

class Dashboard extends LoginRequiredMixin(View) { async get(c) { … } }
class Publish extends PermissionRequiredMixin(View) { permissionRequired = 'blog.publish_post' }
class Mine extends UserPassesTestMixin(View) { testFunc(c) { return getUser(c).isStaff } }
```

Anonymous browsers are redirected to `LOGIN_URL?next=/path/`; JSON clients get 401. Authenticated users
without access get 403 (`raiseException: true` always answers 403).

## Auth views

```ts
import { authUrls } from '@ghuri/auth'
path('accounts/', include(authUrls))
```

| URL | Name | |
|---|---|---|
| `login/` | `login` | `POST {username, password}` (JSON or form). JSON → `{ user }`; forms redirect to a safe `next` or `LOGIN_REDIRECT_URL`. `GET` → `{ csrfToken }` or a minimal HTML form |
| `logout/` | `logout` | `POST` only |
| `password_change/` | `password_change` | `POST {oldPassword, newPassword1, newPassword2}`, login required |
| `password_reset/` | `password_reset` | `POST {email}` → calls `sendResetEmail(c, { user, uid, token, url })` |
| `reset/<uidb64>/<token>/` | `password_reset_confirm` | `GET` checks, `POST {newPassword1, newPassword2}` sets |
| `me/` | `whoami` | current user |

There is no mail package yet: subclass `PasswordResetView` (or `PasswordResetView.asView({ sendResetEmail })`)
to deliver links. `PasswordResetTokenGenerator` / `defaultTokenGenerator` produce Django-compatible tokens
(`PASSWORD_RESET_TIMEOUT`, default 3 days; invalidated by password change and new logins).

## API tokens and JWT

DRF-style tokens (`AuthTokenConfig`): one 40-hex-char key per user, sent as `Authorization: Token <key>`.

```ts
const [token] = await Token.objects.getOrCreate({ user })
```

JWT (simplejwt semantics, signed with `hono/jwt`, HS256 + `SECRET_KEY` by default):

```ts
JWT: {
  ACCESS_TOKEN_LIFETIME: 300,          // seconds
  REFRESH_TOKEN_LIFETIME: 86400,
  ROTATE_REFRESH_TOKENS: true,
  BLACKLIST_AFTER_ROTATION: true,      // needs TokenBlacklistConfig
  ALGORITHM: 'HS256',                  // or RS256/ES256/EdDSA… with SIGNING_KEY / VERIFYING_KEY (PEM)
  // AUDIENCE, ISSUER, LEEWAY, AUTH_HEADER_TYPES ['Bearer'], USER_ID_FIELD 'id', USER_ID_CLAIM 'user_id', …
}
```

```ts
const refresh = await RefreshToken.forUser(user)       // recorded as outstanding when the blacklist app is on
refresh.set('tenant', 't1')                            // custom claims are copied to access tokens
const access = refresh.accessToken
await access.encode(); await refresh.encode()
const t = await AccessToken.fromString(raw)            // throws TokenError (bad signature, expired, wrong type)
await refresh.blacklist()
```

`ghuri flushexpiredtokens` removes expired outstanding tokens; `ghuri drf_create_token <username> [--reset]`.

## REST authentication (`@ghuri/auth/rest`)

```ts
import { JWTAuthentication, SessionAuthentication, TokenAuthentication } from '@ghuri/auth/rest'

REST_FRAMEWORK: { DEFAULT_AUTHENTICATION_CLASSES: [SessionAuthentication, TokenAuthentication, JWTAuthentication] }
```

| Class | Credentials |
|---|---|
| `SessionAuthentication` | the session; **enforces CSRF** on unsafe methods for authenticated users |
| `TokenAuthentication` | `Authorization: Token <key>` (`keyword` / `model` overridable) |
| `JWTAuthentication` | `Authorization: Bearer <access token>` |
| `BasicAuthentication` | `Authorization: Basic …` |
| `RemoteUserAuthentication` | a trusted proxy header |

They implement `authenticate(c): Promise<[user, auth] | null>` and `authenticateHeader(c)` and don't import
`@ghuri/rest`. Failures throw `AuthenticationFailed` / `InvalidToken` (401, `{ detail, code }` with
`WWW-Authenticate`).

Token endpoints (CSRF-exempt, JSON):

```ts
import { obtainAuthToken, TokenBlacklistView, TokenObtainPairView, TokenRefreshView, TokenVerifyView } from '@ghuri/auth/rest'

path('api/auth/token/', obtainAuthToken),                        // {username, password} → {token}
path('api/auth/jwt/', TokenObtainPairView.asView()),             // → {refresh, access}
path('api/auth/jwt/refresh/', TokenRefreshView.asView()),        // {refresh} → {access, refresh?}
path('api/auth/jwt/verify/', TokenVerifyView.asView()),          // {token} → 200 / 401
path('api/auth/jwt/blacklist/', TokenBlacklistView.asView()),    // {refresh} → revoke
```

## Signing

A port of `django.core.signing` (same salts and wire format as Django, HMAC-SHA256 with `SECRET_KEY`;
`SECRET_KEY_FALLBACKS` accepted when verifying):

```ts
import { dumps, loads, Signer, TimestampSigner } from '@ghuri/auth'

const s = await dumps({ userId: 1 }, { salt: 'unsubscribe', compress: true })
await loads(s, { salt: 'unsubscribe', maxAge: 3600 })     // BadSignature / SignatureExpired
await new Signer({ salt: 'x' }).sign('value')             // 'value:signature'
await new TimestampSigner().unsign(signed, 60)
```

## Commands

| Command | |
|---|---|
| `createsuperuser` | Interactive: prompts for `USERNAME_FIELD`, `REQUIRED_FIELDS` and the password twice, runs the validators (offers to bypass). Non-interactive: `--no-input --username admin --email a@b.c` with `--password` or `GHURI_SUPERUSER_PASSWORD` (and `GHURI_SUPERUSER_<FIELD>`); without a password the user gets an unusable one. |
| `changepassword [username]` | Prompts twice (3 attempts) or `--password`. |
| `clearsessions` | Delete expired database sessions. |
| `drf_create_token <username> [--reset]` | Create / reset an API token. |
| `flushexpiredtokens` | Delete expired outstanding JWT refresh tokens. |

## Testing

Importing `@ghuri/auth` registers the test client hooks:

```ts
const client = createTestClient(app, { env })
await client.forceLogin(user)
await client.login({ username: 'ann', password: 'pw' })   // true / false
await client.logout()
```

Use a fast hasher in tests: `PASSWORD_HASHERS: [new PBKDF2PasswordHasher({ iterations: 1000 })]`. After
flushing a test database, call `ContentType.objects.clearCache()`.

## Settings reference

`AUTH_USER_MODEL`, `AUTHENTICATION_BACKENDS`, `PASSWORD_HASHERS`, `AUTH_PASSWORD_VALIDATORS`,
`SECRET_KEY_FALLBACKS`, `LOGIN_URL` (`/accounts/login/`), `LOGIN_REDIRECT_URL` (`/accounts/profile/`),
`LOGOUT_REDIRECT_URL`, `PASSWORD_RESET_TIMEOUT`, `SESSION_*` (above), `SESSION_KV_BINDING`,
`SESSION_CACHE_ALIAS`, `REMOTE_USER_HEADER`, `JWT` (alias `SIMPLE_JWT`). All are typed on `GhuriSettings`.

## Moving from Django

- Tables and columns match Django's (`auth_user`, `auth_user_groups`, `django_content_type`, `django_session`,
  `authtoken_token`, `token_blacklist_*`), so `dumpdata` / `loaddata` fixtures load directly.
- Password hashes (`pbkdf2_sha256`, `pbkdf2_sha1`, `scrypt`) verify unchanged and are upgraded on login.
- `signing.dumps` values, password-reset tokens and session payload encoding are byte-compatible given the same
  `SECRET_KEY` (session keys stored by Django reference Django backend paths, so users log in again).
- bcrypt / argon2 / MD5 hashes are not supported (not available in WebCrypto); reset those passwords.

## Differences from Django

- Everything touching the database or crypto is `async` (`await user.checkPassword()`, `await session.get()`).
- Model inheritance is linear: `PermissionsMixin` extends `AbstractBaseUser`.
- `UserManager` handles any `USERNAME_FIELD` and also takes an object.
- Login-required decorators answer 401 to JSON clients and 403 (not a login redirect) to logged-in users.
- `CHECK_REVOKE_TOKEN` hashes the password with SHA-256 (simplejwt uses MD5, missing from WebCrypto).
- Password-reset timestamps are UTC (Django uses the server's local time — identical on UTC servers).

## License

MIT
