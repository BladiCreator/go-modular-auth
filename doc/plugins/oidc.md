# GoModularAuth OpenID Connect (OIDC) Relying Party Plugin

`gomodularauth-oidc` provides OpenID Connect Relying Party (client) authentication and federated identity integration for GoModularAuth.

It implements RFC 6749, RFC 7636 (PKCE), and OpenID Connect Core 1.0 specifications with rigorous zero-trust ID token verification, strict nonce binding, multi-provider discovery, and account linking.

---

## 1. Problem Solved

Modern web applications frequently delegate user authentication to identity providers (Google, Microsoft Entra, Okta, Keycloak, Auth0, Apple) using OpenID Connect.
However, naive OIDC client implementations suffer from severe vulnerabilities:
- Trusting unverified JWT claims before signature checks.
- Accepting forged signatures or missing signature validation.
- Missing nonce validation allowing ID Token replay attacks.
- Blind account takeover via unverified email collisions.
- Session confusion between state generation and token callback.

`gomodularauth-oidc` resolves these concerns cleanly:
- **Zero-Trust Token Validation**: Never deserializes or trusts claims until the cryptographic JWS signature is verified against the provider's JWKS.
- **Strict OIDC Core 1.0 Invariants**: Validates `iss` (issuer), `aud`/`azp` (audience), `exp` (expiration), `iat` (issued at), and `nonce` (anti-replay).
- **Cryptographic S256 PKCE & Nonce**: Every authorization request generates high-entropy PKCE code verifiers and single-use nonces.
- **Atomic State Sessions**: In-flight state sessions are single-use (`consumed_at`), preventing CSRF and replay attacks.
- **Account Linking & Collision Policies**: Protects against account hijacking by enforcing email verification requirements (`LinkingPolicyVerifiedEmail` or `LinkingPolicyExplicitOnly`).
- **Core Integration**: Seamlessly maps external federated identities to Core `User`, `Account`, and server-side `Session`.

---

## 2. Installation

```bash
go get github.com/BladiCreator/go-modular-auth-oidc
```

---

## 3. Configuration

```go
import (
    "time"
    auth "github.com/BladiCreator/go-modular-auth"
    oidc "github.com/BladiCreator/go-modular-auth-oidc"
    oidcmemory "github.com/BladiCreator/go-modular-auth-oidc/store/memory"
)

// Configure OIDC Provider
googleConfig := oidc.ProviderConfig{
    ID:           "google",
    Issuer:       "https://accounts.google.com",
    ClientID:     os.Getenv("GOOGLE_CLIENT_ID"),
    ClientSecret: os.Getenv("GOOGLE_CLIENT_SECRET"),
    RedirectURI:  "https://myauthapp.com/api/auth/oidc/google/callback",
    Scopes:       []string{"openid", "profile", "email"},
}

// Instantiate Plugin
oidcPlugin := oidc.New(
    oidc.WithProvider(googleConfig),
    oidc.WithStore(oidcmemory.New()), // Use database store adapter in production
    oidc.WithStateTTL(10 * time.Minute),
    oidc.WithLinkingPolicy(oidc.LinkingPolicyVerifiedEmail),
)
```

---

## 4. Registration in GoModularAuth

```go
engine, err := auth.New(auth.Config{
    Store: coreStore,
    Cache: coreCache,
    Plugins: []auth.PluginModule{
        oidcPlugin,
    },
})
if err != nil {
    log.Fatalf("failed to initialize auth: %v", err)
}

// Access typed capability
oidcAuth, err := auth.Get[plugins.OIDC](engine)
if err != nil {
    log.Fatalf("failed to resolve OIDC capability: %v", err)
}
```

---

## 5. Public API

```go
type OIDC interface {
    // BeginAuth initiates an OIDC authorization code flow with PKCE and Nonce.
    BeginAuth(ctx context.Context, in BeginAuthInput) (*BeginAuthResult, error)

    // CompleteAuth exchanges the authorization code, validates the ID token, and issues a Core Session.
    CompleteAuth(ctx context.Context, in CompleteAuthInput) (*AuthResult, error)

    // BeginLink initiates an explicit account linking ceremony for an authenticated user.
    BeginLink(ctx context.Context, in BeginLinkInput) (*BeginAuthResult, error)

    // CompleteLink finalizes account linking.
    CompleteLink(ctx context.Context, in CompleteLinkInput) (*LinkResult, error)

    // UnlinkAccount detaches an external OIDC account from a user.
    UnlinkAccount(ctx context.Context, userID, provider string) error

    // ListAccounts lists all external OIDC accounts linked to a user.
    ListAccounts(ctx context.Context, userID string) ([]*account.Account, error)

    // GetProvider returns the configuration for a registered provider.
    GetProvider(providerID string) (*ProviderConfig, error)

    // RegisterProvider dynamically adds or updates an OIDC provider.
    RegisterProvider(cfg ProviderConfig) error
}
```

---

## 6. Dependencies

| Dependency | Purpose | Rationale |
| :--- | :--- | :--- |
| `github.com/BladiCreator/go-modular-auth` | Core GoModularAuth engine | User, Account, Session, and Store models |
| `github.com/BladiCreator/go-modular-auth/plugin-sdk` | Plugin runtime SDK | Modular dependency injection & registration |
| Standard Library (`crypto/*`, `net/http`) | Pure Go Cryptography & Networking | No third-party JWT or crypto dependencies needed; standard library handles RSA, ECDSA, HMAC, SHA256, and base64. |

---

## 7. Persistence

The plugin defines a clean persistence contract for in-flight state sessions:

```go
type Store interface {
    SaveState(ctx context.Context, s *StateSession) error
    GetState(ctx context.Context, state string) (*StateSession, error)
    ConsumeState(ctx context.Context, state string, now time.Time) (*StateSession, error)
    DeleteState(ctx context.Context, state string) error
    PurgeExpired(ctx context.Context, before time.Time) (int, error)
}
```

State sessions are stored persistently with atomic single-use (`consumed_at`) guarantees.
PostgreSQL migration schemas are located in `migrations/001_create_oidc_tables.sql`.

---

## 8. Cache

- **JWKS Cache**: Cryptographic keys retrieved from `/.well-known/openid-configuration` -> `jwks_uri` are cached in-memory with automatic TTL expiration and cache-invalidation on key rotation.
- **State Store**: The Store remains the single source of truth for security-sensitive state sessions.

---

## 9. Events

The plugin emits structured audit events through Core's Event system:

- `oidc.authenticated`: Emitted upon successful OIDC sign-in or registration.
- `oidc.account_linked`: Emitted when an external OIDC account is linked to an existing user.
- `oidc.account_unlinked`: Emitted when an external OIDC account is disconnected.
- `oidc.failed`: Emitted on signature verification failures, nonce mismatches, or invalid states.

---

## 10. Security Invariants

1. **Zero-Trust ID Token Validation**: JWS signatures are verified using provider public keys before any claim payload is parsed or trusted.
2. **Strict Nonce Binding**: A cryptographically random nonce generated during `BeginAuth` is bound to the state session and compared against the `nonce` claim in the ID Token.
3. **PKCE (RFC 7636)**: High-entropy code verifier with S256 challenge is enforced for all code flows.
4. **Single-Use State Sessions**: `ConsumeState` marks `consumed_at` atomically, preventing CSRF replays.
5. **Sole Authentication Method Protection**: Users cannot unlink an external account if they have no other credentials (passwords, other providers), preventing account lockout.
6. **Account Takeover Prevention**: Account linking prevents hijacking across providers by enforcing `LinkingPolicyVerifiedEmail` or requiring prior interactive sign-in (`LinkingPolicyExplicitOnly`).

---

## 11. Testing

The plugin contains comprehensive unit, integration, and security test suites using an in-process mock OpenID Provider:

```bash
go test -v -race ./...
```
