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
For local password authentication, `Provider` is `account.ProviderPassword` (`"password"`) and `ProviderID` is the `UserID`. External plugins (OAuth, Passkeys, SAML) map their provider identifiers through `Account`.

### 1.3 `Credential` (`credential.Credential`)
Holds authentication material decoupled from the account:

```go
type Credential struct {
    ID        string
    UserID    string
    AccountID string
    Type      Type // TypePassword, etc.
    Secret    string
    CreatedAt time.Time
    UpdatedAt time.Time
    RevokedAt *time.Time
}
```
`Secret` never holds plaintext data. For passwords, it stores an encoded Argon2id hash. Plugins attach credentials (e.g. WebAuthn public keys, recovery codes) by specifying their own `credential.Type`.

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
GoModularAuth does not use stateless JWTs for sessions by default. Sessions are opaque tokens with 256-bit entropy generated via `crypto/rand`. Only `TokenHash` (SHA-256) is persisted in the database.

### 1.5 `VerificationToken` (`verification.Token`)
A single-use verification primitive with atomic consumption:

```go
type Token struct {
    ID        string
    Purpose   Purpose // e.g. "email_verification", "password_reset"
    Subject   string  // User ID, email, or client ID
    TokenHash string  // SHA-256 hash of plaintext token
    ExpiresAt time.Time
    UsedAt    *time.Time
    CreatedAt time.Time
}
```

### 1.6 `Principal` (`auth.Principal`) & Context Helpers
The boundary between authentication and authorization:

```go
type Principal struct {
    Subject string
    Type    PrincipalType // PrincipalUser, PrincipalServiceAccount, PrincipalAPIKey
}

// Bind to context
ctx = auth.WithPrincipal(ctx, principal)

// Retrieve from context
principal, ok := auth.PrincipalFrom(ctx)

// Multi-tenant binding
ctx = auth.WithOrganization(ctx, orgID)
orgID, ok := auth.OrganizationFrom(ctx)
```

---

## 2. Core Engine Operations

### 2.1 Initialization (`auth.New`)
```go
import (
    "database/sql"
    auth "github.com/BladiCreator/go-modular-auth"
    "github.com/BladiCreator/go-modular-auth/adapters/postgres"
)

db, _ := sql.Open("pgx", "postgres://user:pass@localhost:5432/authdb?sslmode=disable")

engine, err := auth.New(auth.Config{
    Adapter: postgres.New(db),
})
```
- Validates configuration and applies secure defaults.
- Dynamically compiles and ensures the database schema across Core and all installed plugins.
- Compiles dummy timing hashes to prevent user enumeration attacks.
- Resolves plugin dependency graphs and initializes plugins topologically.

### 2.2 User Registration (`SignUp`)
```go
res, err := engine.SignUp(ctx, auth.SignUpInput{
    Email:    "user@example.com",
    Password: "SecurePassword123!",
    Session: auth.SessionOptions{
        IPAddress: "192.168.1.1",
        UserAgent: "Mozilla/5.0 ...",
    },
})
```
1. Executes `BeforeSignUp` hooks.
2. Normalizes email and validates password against `PasswordPolicy`.
3. Hashes password using Argon2id outside the database transaction (prevents holding database locks during CPU-heavy hashing).
4. Begins an atomic database transaction via `Adapter.Transaction`:
   - Checks email uniqueness (`adapter.ErrConflict`).
   - Persists `User`, `Account`, and `Credential`.
   - Creates `Session` (unless email verification is required).
5. Post-commit:
   - Populates semantic caches (`sessionCache`, `userCache`).
   - Dispatches `EventUserCreated` and `EventSessionCreated`.
   - Sends verification email if configured.
   - Runs `AfterSignUp` hooks.

### 2.3 User Authentication (`SignIn`)
```go
res, err := engine.SignIn(ctx, auth.SignInInput{
    Email:    "user@example.com",
    Password: "SecurePassword123!",
})
```
- **Anti-Enumeration Timing Mitigation**: If the user does not exist, the engine runs password verification against a precomputed dummy hash, ensuring response times are indistinguishable between non-existent users and incorrect passwords.
- Validates credentials and checks email verification status.
- Issues a new session atomically and caches it.

### 2.4 Session Revocation (`SignOut`)
```go
err := engine.SignOut(ctx, auth.SignOutInput{
    Token: tokenString,
})
```
- Idempotent: revoking an unknown or already-revoked session returns `nil`.
- Marks `RevokedAt` in the Store, evicts the session from cache, and publishes `EventSessionRevoked` and `EventUserSignedOut`.

### 2.5 Session Verification (`GetSession` & `RequireSession`)
```go
// Lenient lookup: returns (nil, nil) if token is invalid or expired
res, err := engine.GetSession(ctx, tokenString)

// Strict lookup: returns ErrUnauthorized if invalid or expired
res, err := engine.RequireSession(ctx, tokenString)
```
- Hashes token using SHA-256.
- Queries `cache.SessionCache` (Cache-Aside pattern). On cache miss, queries `Store.Sessions().GetByTokenHash()` and populates cache.
- Validates expiration and revocation status. Loads user details and returns `*SessionResult`.

### 2.6 Plugin Session Issuance (`CreateSession`)
```go
issued, err := engine.CreateSession(ctx, userID, auth.SessionOptions{
    IPAddress: "10.0.0.1",
    UserAgent: "iOS App",
})
// issued.Token is the plaintext token returned to the client
// issued.Session is the persisted domain session
```
Enables external plugins (OAuth, Passkeys, Magic Links, 2FA) to issue valid sessions for existing users.

### 2.7 Password Management & Account Recovery
- **`ChangePassword`**: Verifies existing password, hashes new password, updates credential, and revokes other active sessions unless `KeepOtherSessions: true`.
- **`RequestPasswordReset`**: Issues single-use token and sends reset instructions via configured `email.Sender`.
- **`ResetPassword`**: Atomically consumes the verification token and updates password credential.
- **`VerifyEmail`**: Atomically consumes verification token and sets `EmailVerified = true`.

### 2.8 Single-Use Token Engine (`IssueToken` & `ConsumeToken`)
```go
// Issue single-use token
token, err := engine.IssueToken(ctx, "magic_link", userID, 15*time.Minute)

// Atomically consume token
tok, err := engine.ConsumeToken(ctx, "magic_link", token)
```
- Plaintext token is returned once; only SHA-256 hash is persisted.
- `ConsumeToken` uses atomic compare-and-swap update (`used_at IS NULL`), preventing race conditions and replay attacks.

### 2.9 Background Maintenance (`PurgeExpired`)
```go
sessionsDeleted, tokensDeleted, err := engine.PurgeExpired(ctx)
```
Invoked periodically by background schedulers to clean up expired sessions and consumed verification tokens.

---

## 3. Password Hashing Specification

The core uses **Argon2id** conforming to OWASP recommendations:

- **Time (Iterations)**: 1
- **Memory**: 64 MB (65536 KiB)
- **Threads / Parallelism**: 4
- **Key Length**: 32 bytes
- **Salt Length**: 16 cryptographically random bytes

Hash format: `$argon2id$v=19$m=65536,t=1,p=4$<salt>$<digest>`

---

## 4. Hooks vs Events

| Feature | Hooks (`auth.Hooks`) | Events (`auth.Events`) |
| :--- | :--- | :--- |
| **Execution** | Synchronous during the workflow | Observational, post-commit |
| **Transaction** | Before hooks run **inside** the DB transaction | Runs **after** commit |
| **Veto Power** | Can abort the operation by returning an error | Cannot abort or modify the workflow |
| **Panic Safety** | Propagates errors | Automatically recovers and logs panics |
| **Use Cases** | Input mutation, validation, tenant checks | Audit logging, notifications, telemetry |
