# Changelog

## 0.1.0-alpha.0

- Initial alpha.
- Apps: `ContentTypesConfig` (`contenttypes`), `AuthConfig` (`auth`), `SessionsConfig` (`sessions`),
  `AuthTokenConfig` (`authtoken`), `TokenBlacklistConfig` (`token_blacklist`), with Django table names.
- Models: `AbstractBaseUser`, `PermissionsMixin`, `AbstractUser`, swappable `User` (`AUTH_USER_MODEL`,
  `getUserModel()`), `Group`, `Permission`, `ContentType` (cached `getForModel`), `Session`, `Token`,
  `OutstandingToken`, `BlacklistedToken`; `UserManager` (`createUser`, `createSuperuser`, `normalizeEmail`,
  `getByNaturalKey`, `withPerm`).
- Password hashing on WebCrypto, byte-compatible with Django: `PBKDF2PasswordHasher` (default, 100,000
  iterations), `PBKDF2SHA1PasswordHasher`, `ScryptPasswordHasher` (pure JS); pure-JS PBKDF2 fallback for
  iteration counts Workers refuse; hash upgrades on login.
- Password validators: minimum length, user-attribute similarity, common passwords, numeric.
- `authenticate` / `login` / `logout` / `updateSessionAuthHash`, `ModelBackend`, `AllowAllUsersModelBackend`,
  `RemoteUserBackend`, signals `userLoggedIn` / `userLoggedOut` / `userLoginFailed`.
- Sessions: `SessionMiddleware` with `db`, `kv`, `cache` and `signedCookie` engines; `AuthenticationMiddleware`,
  `RemoteUserMiddleware`.
- `createPermissions()` (hooked into the ORM's `postMigrate` when available), `createContentTypes()`.
- Decorators and mixins: `loginRequired`, `permissionRequired`, `userPassesTest`, `staffMemberRequired`,
  `LoginRequiredMixin`, `PermissionRequiredMixin`, `UserPassesTestMixin`.
- JSON-first auth views and `authUrls`; Django-compatible `PasswordResetTokenGenerator`.
- `django.core.signing` port (`Signer`, `TimestampSigner`, `dumps`, `loads`).
- JWT (`AccessToken`, `RefreshToken`, rotation, blacklist) on `hono/jwt`.
- `@ghuri/auth/rest`: `SessionAuthentication`, `TokenAuthentication`, `JWTAuthentication`,
  `BasicAuthentication`, `RemoteUserAuthentication`; `obtainAuthToken`, `TokenObtainPairView`,
  `TokenRefreshView`, `TokenVerifyView`, `TokenBlacklistView`.
- Commands: `createsuperuser`, `changepassword`, `clearsessions`, `drf_create_token`, `flushexpiredtokens`.
- Test client hooks: `client.forceLogin()`, `client.login()`, `client.logout()`.
