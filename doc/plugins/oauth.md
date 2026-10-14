# GoModularAuth OAuth Plugin (`gomodularauth-oauth`)

Generic, provider-agnostic OAuth 2.0 and OpenID Connect (OIDC) client plugin for [GoModularAuth](https://github.com/BladiCreator/go-modular-auth).

Provides enterprise-grade authentication via external identity providers (Google, GitHub, GitLab, Discord, Microsoft, Keycloak, Auth0, etc.) with strict adherence to RFC 6749, RFC 7636 (PKCE), cryptographically validated state anti-replay protection, safe account linking policies, and native integration with GoModularAuth Core.

---

## 1. Features

- **Provider-Agnostic Architecture**: Connect any RFC 6749 / OpenID Connect compliant identity provider without changing core code.
- **PKCE by Default (RFC 7636)**: Generates high-entropy `code_verifier` secrets and enforces SHA-256 (`S256`) code challenges for every flow.
- **Cryptographic State & Replay Protection**: Single-use, atomic state consumption prevents CSRF and code reuse replay attacks.
- **Strict Redirect URI Validation**: Whitelist validation at flow initiation and callback verification.
- **Unsafe Automatic Account Linking Prevention**: Explicit linking policies (`LinkingPolicyExplicitOnly`, `LinkingPolicyVerifiedEmail`, `LinkingPolicyDisabled`) prevent account takeover vulnerabilities.
- **Seamless Core Integration**: Reuses Core `user.User`, `account.Account`, and creates genuine Core `session.Session` opaque tokens upon authentication.
- **No HTTP Framework Lock-in**: Transport-agnostic domain capability usable from `net/http`, Gin, Fiber, Echo, gRPC, or CLI workers.
- **Extensible Hooks and Observability**: Audit logging events and lifecycle interceptors for fine-grained workflow control.
- **Dual Store Adapters**: Built-in thread-safe Memory store and production-ready PostgreSQL store.

---

## 2. Architecture

```text
[ HTTP Transport / Web Framework (Gin, Echo, net/http) ]
                          │
                          ▼
            [ GoModularAuth Core Auth Engine ]
                          │
                          ▼
          [ gomodularauth-oauth Plugin Capability ]
                 │                  │
                 ▼                  ▼
      [ Provider Contract ]  [ State Store ]
       - Google               - Memory Store
       - GitHub               - PostgreSQL Store
       - Generic OIDC
```

The plugin integrates strictly with GoModularAuth's capability architecture:
```go
oauthCapability, err := auth.Get[plugins.OAuth](engine)
```

---

## 3. Installation

```bash
go get github.com/BladiCreator/go-modular-auth-oauth
```

---

## 4. Configuration and Registration

```go
package main

import (
	"log"
	"net/http"

	"github.com/BladiCreator/go-modular-auth/auth"
	memstore "github.com/BladiCreator/go-modular-auth/store/memory"

	oauth "github.com/BladiCreator/go-modular-auth-oauth"
	"github.com/BladiCreator/go-modular-auth-oauth/plugins"
	"github.com/BladiCreator/go-modular-auth-oauth/provider"
)

func main() {
	// 1. Configure OAuth Identity Providers
	googleProvider, err := provider.NewGoogleProvider(provider.ProviderCommonConfig{
		ClientID:            "YOUR_GOOGLE_CLIENT_ID",
		ClientSecret:        "YOUR_GOOGLE_CLIENT_SECRET",
		AllowedRedirectURIs: []string{"https://mycompany.com/auth/callback/google"},
	})
	if err != nil {
		log.Fatal(err)
	}

	githubProvider, err := provider.NewGitHubProvider(provider.ProviderCommonConfig{
		ClientID:            "YOUR_GITHUB_CLIENT_ID",
		ClientSecret:        "YOUR_GITHUB_CLIENT_SECRET",
		AllowedRedirectURIs: []string{"https://mycompany.com/auth/callback/github"},
	})
	if err != nil {
		log.Fatal(err)
	}

	// 2. Initialize the OAuth Plugin Module
	oauthModule := oauth.New(
		oauth.WithProviders(googleProvider, githubProvider),
		oauth.WithDefaultPKCE(true),
		oauth.WithLinkingPolicy(oauth.LinkingPolicyExplicitOnly), // Prevent unsafe auto-linking
		oauth.WithAllowSignUp(true),
	)

	// 3. Register Plugin in GoModularAuth
	engine, err := auth.New(auth.Config{
		Store:   memstore.New(),
		Plugins: []auth.PluginModule{oauthModule},
	})
	if err != nil {
		log.Fatal(err)
	}

	// 4. Retrieve Strongly-Typed Capability
	oauthAuth, err := auth.Get[plugins.OAuth](engine)
	if err != nil {
		log.Fatal(err)
	}

	_ = oauthAuth
}
```

---

## 5. Public Capability API

```go
type OAuth interface {
    // BeginAuth initiates an OAuth authorization flow for login/sign-up.
    BeginAuth(ctx context.Context, in BeginAuthInput) (*BeginAuthResult, error)

    // BeginLink initiates an OAuth authorization flow for account linking.
    BeginLink(ctx context.Context, in BeginLinkInput) (*BeginAuthResult, error)

    // CompleteAuth consumes state, exchanges code for tokens, retrieves profile, and issues a Core Session.
    CompleteAuth(ctx context.Context, in CompleteAuthInput) (*AuthResult, error)

    // CompleteLink links the external provider identity to an authenticated Core user.
    CompleteLink(ctx context.Context, in CompleteLinkInput) (*LinkResult, error)

    // UnlinkAccount removes the link between a user and an OAuth provider.
    UnlinkAccount(ctx context.Context, userID, provider string) error

    // ListAccounts returns all external OAuth accounts linked to the user.
    ListAccounts(ctx context.Context, userID string) ([]*account.Account, error)

    // GetProvider returns a registered provider by name.
    GetProvider(name string) (provider.Provider, error)

    // PurgeExpired cleans up expired state sessions.
    PurgeExpired(ctx context.Context) (int, error)
}
```

---

## 6. Safe Account Linking Policies

Automatic account linking based purely on email match creates serious account takeover vulnerabilities if an attacker registers an unverified email at an external provider.

`gomodularauth-oauth` enforces three explicit policies:

| Policy | Behavior | Security Posture |
| :--- | :--- | :--- |
| `LinkingPolicyExplicitOnly` *(Default)* | If email matches an existing user, returns `ErrAccountLinkingRequiresConsent`. User must log in first and link the account explicitly via `BeginLink`/`CompleteLink`. | **Highest**. Recommended for all production apps. |
| `LinkingPolicyVerifiedEmail` | Automatically links accounts only if BOTH external provider asserts `EmailVerified == true` AND Core User has `EmailVerified == true`. Returns `ErrUnverifiedEmailLinkingProhibited` otherwise. | **Medium**. Suitable for trusted corporate IdPs. |
| `LinkingPolicyDisabled` | Completely disallows account linking. Returns `ErrAccountConflict` on duplicate emails. | **Strict**. |

---

## 7. PostgreSQL Persistence & Migrations

For production deployments, configure the PostgreSQL state store:

```go
import (
    "database/sql"
    _ "github.com/jackc/pgx/v5/stdlib"
    pgstore "github.com/BladiCreator/go-modular-auth-oauth/store/postgres"
)

db, _ := sql.Open("pgx", "postgres://user:pass@localhost:5432/auth_db")
oauthModule := oauth.New(
    oauth.WithStore(pgstore.New(db)),
    // ...
)
```

Run schema migration:
```bash
psql -d auth_db -f migrations/001_create_oauth_tables.sql
```

---

## 8. Events & Hooks

### Events
Subscribers receive observational events through `engine.Events()`:
- `oauth.state_created`
- `oauth.authenticated`
- `oauth.user_created`
- `oauth.account_linked`
- `oauth.account_unlinked`
- `oauth.failed`

### Hooks
Intercept workflows programmatically:
```go
hooks := oauth.NewHooks()
hooks.BeforeOAuthRedirect(func(ctx context.Context, in *oauth.BeginAuthInput) error {
    log.Println("Initiating flow for provider:", in.Provider)
    return nil
})
hooks.AfterOAuthSignIn(func(ctx context.Context, res *oauth.AuthResult) error {
    log.Printf("User %s signed in via OAuth (New: %v)", res.User.Email, res.IsNewUser)
    return nil
})
```

---

## 9. Testing

```bash
go test -v -race ./...
```

---

## 10. License

MIT License. Copyright (c) 2026 Vladimir.
