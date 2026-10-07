# Core Engine & Domain Operations

## 1. Core Entities

The core domain defines minimal, cohesive entities:

### 1.1 `User` (`user.User`)
Represents an identity:

```go
type User struct {
    ID            string
    Email         string
    EmailVerified bool
    CreatedAt     time.Time
    UpdatedAt     time.Time
}
```
Emails are automatically normalized using `user.NormalizeEmail` (lowercase, whitespace trimmed, parsed according to RFC 5322).

### 1.2 `Account` (`account.Account`)
Represents an association between a `User` and an authentication provider:

```go
type Account struct {
    ID         string
    UserID     string
    Provider   string
    ProviderID string
    CreatedAt  time.Time
    UpdatedAt  time.Time
}
```
For local password authentication, `Provider` is `"password"` and `ProviderID` is the `UserID`. External plugins (OAuth, Passkeys) map their provider identifiers through `Account`.

### 1.3 `Credential` (`credential.Credential`)
Holds authentication material decoupled from the account:

```go
type Credential struct {
    ID        string
    UserID    string
    AccountID string
    Type      Type
    Secret    string
    CreatedAt time.Time
    UpdatedAt time.Time
    RevokedAt *time.Time
}
```
`Secret` never holds plaintext data. For passwords, it stores an encoded Argon2id hash. Plugins attach credentials (e.g. public keys, recovery codes) by specifying their own `credential.Type`.

### 1.4 `Session` (`session.Session`)
Represents an opaque server-side session:

```go
type Session struct {
    ID        string
    UserID    string
    TokenHash string
    IPAddress string
    UserAgent string
    ExpiresAt time.Time
    RevokedAt *time.Time
    CreatedAt time.Time
}
```
GoModularAuth does not use stateless JWTs for sessions by default. Sessions are opaque tokens with 256-bit entropy generated via `crypto/rand`. Only `TokenHash` (SHA-256) is persisted.

### 1.5 `VerificationToken` (`verification.Token`)
Generic primitive for single-use, expiring actions:

```go
type Token struct {
    ID        string
    Purpose   Purpose
    Subject   string
    TokenHash string
    ExpiresAt time.Time
    UsedAt    *time.Time
    CreatedAt time.Time
}
```
Used for email verification (`email_verification`), password resets (`password_reset`), and plugins (magic links, one-time tokens, device authorization).

### 1.6 `Principal` (`auth.Principal`)
The identity passed across the boundary from authentication to authorization:

```go
type Principal struct {
    Subject string
    Type    PrincipalType // "user", "service_account", "api_key"
}
```

---

## 2. Password Hashing (`password.Hasher`)

Password hashing is abstracted behind the `Hasher` interface:

```go
type Hasher interface {
    Hash(ctx context.Context, password string) (string, error)
    Verify(ctx context.Context, hash, password string) error
}
```

### Argon2id Implementation
GoModularAuth ships with an Argon2id implementation as default, adhering to OWASP recommendations:

- **Memory**: 19 MiB (19,456 KiB)
- **Iterations**: 2
- **Parallelism**: 1
- **Salt length**: 16 bytes
- **Key length**: 32 bytes

Hashes follow the standard PHC string format:
```text
$argon2id$v=19$m=19456,t=2,p=1$<base64-salt>$<base64-key>
```
Parameters are encoded into the hash, allowing algorithm cost increases over time without invalidating existing passwords.

---

## 3. Core Engine Operations

### 3.1 Sign Up (`auth.SignUp`)
Creates `User + Account + Credential + Session` in a single atomic database transaction:

```go
res, err := app.SignUp(ctx, auth.SignUpInput{
    Email:    "user@example.com",
    Password: "SecurePassword123!",
    Session: auth.SessionOptions{
        IPAddress: "192.168.1.10",
        UserAgent: "Mozilla/5.0 ...",
    },
})
```
- If `EmailVerification.Required` is set to `true`, no session is issued until the email address is verified.
- Emits `auth.EventUserCreated` upon successful commit.

### 3.2 Sign In (`auth.SignIn`)
Authenticates email and password:

```go
res, err := app.SignIn(ctx, auth.SignInInput{
    Email:    "user@example.com",
    Password: "SecurePassword123!",
})
```
- **Timing Equalization**: If the user email does not exist, Argon2id verification is still run against a dummy hash to prevent user enumeration via timing analysis.
- Emits `auth.EventUserSignedIn`.

### 3.3 Sign Out (`auth.SignOut`)
Idempotently revokes the session matching the given plaintext token:

```go
err := app.SignOut(ctx, auth.SignOutInput{
    Token: token,
})
```
- Revokes in Store, deletes from Cache, and emits `auth.EventUserSignedOut` and `auth.EventSessionRevoked`.

### 3.4 Session Validation (`GetSession` & `RequireSession`)
Resolves an opaque bearer/cookie token:

```go
// Returns (nil, nil) if token is invalid or expired
res, err := app.GetSession(ctx, token)

// Returns auth.ErrUnauthenticated if token is invalid or expired
res, err := app.RequireSession(ctx, token)
```
Utilizes **Cache-Aside**: checks cache first, queries the Store on miss, populates cache with remaining TTL, and validates user existence.

### 3.5 Password Management
- **`ChangePassword`**: Verifies old password, creates a new credential, revokes older credentials, and revokes all other active sessions (unless `KeepOtherSessions: true`).
- **`RequestPasswordReset`**: Issues a single-use verification token and delivers it via `email.Sender`. Always returns `nil` for unknown emails to eliminate enumeration.
- **`ResetPassword`**: Atomically consumes the verification token, rotates the password credential, and revokes all active sessions for the user.
- **`VerifyEmail`**: Atomically consumes the verification token and marks `EmailVerified = true`.

---

## 4. Configuration & Secure Zero-Value Defaults

GoModularAuth is configured via `auth.Config`. Only `Store` is mandatory; all other fields fall back to secure, hardened defaults:

```go
type Config struct {
    Store             store.Store             // Required
    Cache             cache.Cache             // Optional: nil operates directly against Store
    Email             email.Sender            // Optional: required only for email verification / reset
    Hasher            password.Hasher         // Defaults to Argon2id (OWASP params)
    Plugins           []PluginModule          // Installed plugins
    Logger            *slog.Logger            // Defaults to slog.DiscardHandler
    Now               func() time.Time        // Clock, defaults to time.Now
    Session           SessionConfig
    User              UserConfig
    Password          PasswordPolicy
    EmailVerification EmailVerificationConfig
    PasswordReset     PasswordResetConfig
    Messages          Messages
}
```

### 4.1 Default Values & Policy Matrix

| Setting | Field | Default Value | Description |
| :--- | :--- | :--- | :--- |
| **Hasher** | `Config.Hasher` | Argon2id (`m=19MiB, t=2, p=1`) | OWASP compliant memory-hard password hasher. |
| **Session Lifetime** | `Session.TTL` | `7 * 24 * time.Hour` (7 days) | Total validity period of an issued session. |
| **Session Cache TTL** | `Session.CacheTTL` | `5 * time.Minute` | Upper bound for cached sessions, mitigating stale read windows. |
| **User Cache TTL** | `User.CacheTTL` | `5 * time.Minute` | Cache duration for user entities. |
| **Min Password Length** | `Password.MinLength` | `8` bytes | Minimum password length requirement. |
| **Max Password Length** | `Password.MaxLength` | `128` bytes | Protects Argon2id from Denial of Service (DoS) attacks. |
| **Email Verification TTL** | `EmailVerification.TokenTTL` | `24 * time.Hour` | Validity duration of email confirmation tokens. |
| **Password Reset TTL** | `PasswordReset.TokenTTL` | `1 * time.Hour` | Validity duration of password reset tokens. |
| **Require Verified Email** | `EmailVerification.Required` | `false` | If `true`, blocks session issuance on SignUp and rejects SignIn. |
| **Send Verification Email** | `EmailVerification.SendOnSignUp` | `false` | If `true`, dispatches verification email right after SignUp. |

