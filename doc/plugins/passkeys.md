# GoModularAuth - Passkey Plugin (`gomodularauth-passkey`)

Provides WebAuthn and Passkey registration and authentication as an optional server-side authentication mechanism for [GoModularAuth](https://github.com/BladiCreator/go-modular-auth).

## Features

- **FIDO2 / WebAuthn Compliant**: Built on top of `github.com/go-webauthn/webauthn` v0.11.2 (official W3C Level 3 standard).
- **Zero Cryptographic Reinvention**: Fully delegates COSE parsing, CBOR decoding, attestation checks, and signature verification to mature cryptographic implementations.
- **Discoverable Credentials**: Supports usernameless / resident-key logins (`navigator.credentials.get()`) without requiring pre-filled usernames.
- **User Verification & Resident Key Policies**: Granular configuration for `Required`, `Preferred`, and `Discouraged` policies.
- **Replay & Clone Attack Prevention**:
  - Transient ceremony challenges with single-use atomic consumption and strict expiration.
  - Sign counter regression detection (`CloneWarning`) to detect and block cloned authenticators.
- **Protocol-Independent**: Does not introduce HTTP handlers or bind to `net/http`. Works seamlessly with HTTP, gRPC, WebSockets, or CLI adapters by accepting `[]byte`, `io.Reader`, or pre-parsed structures.
- **Reuses Core Entities**: Integrates seamlessly with GoModularAuth Core `User`, `Account`, and `Session` models.
- **Observability**: Emits non-sensitive `passkey.registered`, `passkey.used`, and `passkey.revoked` events.
- **Storage Adapters**: Includes thread-safe in-memory implementations for testing and a standard PostgreSQL adapter.

---

## Installation

```bash
go get github.com/BladiCreator/go-modular-auth-passkeys
```

---

## Configuration

The plugin is configured using functional options:

```go
passkey.New(
    passkey.WithRP("example.com", "Acme Corporation", []string{
        "https://example.com",
        "https://auth.example.com",
    }),
    passkey.WithUserVerification(protocol.VerificationPreferred),
    passkey.WithResidentKey(protocol.ResidentKeyRequirementPreferred),
    passkey.WithTimeout(60 * time.Second),
    passkey.WithEnforceSignCounter(true),
    passkey.WithStore(postgresStore), // or in-memory store
)
```

### Configuration Parameters

| Option | Type | Default | Description |
|---|---|---|---|
| `RPID` | `string` | **Required** | Relying Party domain (cannot contain scheme or port). |
| `RPDisplayName` | `string` | **Required** | Human-readable service name presented to the user. |
| `RPOrigins` | `[]string` | **Required** | Allowed fully qualified client origins (`https://...`). |
| `UserVerification` | `protocol.UserVerificationRequirement` | `preferred` | Verification policy: `required`, `preferred`, `discouraged`. |
| `ResidentKey` | `protocol.ResidentKeyRequirement` | `preferred` | Resident key policy for discoverable credentials. |
| `Timeout` | `time.Duration` | `60s` | Expiration window for registration/authentication ceremonies. |
| `EnforceSignCounter`| `bool` | `true` | Validates sign counters and blocks authenticator clones. |
| `Store` | `store.Store` | Memory Store | Authoritative persistence for passkey credentials. |
| `ChallengeStore` | `challenge.Store` | Memory Store | Storage adapter for active ceremony challenges. |

---

## Registration in GoModularAuth

```go
package main

import (
	"log"
	"time"

	passkey "github.com/BladiCreator/go-modular-auth-passkeys"
	"github.com/BladiCreator/go-modular-auth-passkeys/plugins"
	"github.com/BladiCreator/go-modular-auth/auth"
	"github.com/BladiCreator/go-modular-auth/store/memory"
)

func main() {
	passkeyMod := passkey.New(
		passkey.WithRP("localhost", "My App", []string{"http://localhost:3000"}),
		passkey.WithTimeout(60 * time.Second),
	)

	authEngine, err := auth.New(auth.Config{
		Store:   memory.New(),
		Plugins: []auth.PluginModule{passkeyMod},
	})
	if err != nil {
		log.Fatalf("failed to initialize auth: %v", err)
	}

	// Retrieve typed capability
	pk, err := auth.Get[plugins.Passkeys](authEngine)
	if err != nil {
		log.Fatalf("failed to retrieve passkey capability: %v", err)
	}

	_ = pk
}
```

---

## Public API (`Passkeys`)

The capability exposes protocol-independent domain operations:

```go
type Passkeys interface {
	// Ceremony: Registration
	BeginRegistration(ctx context.Context, in BeginRegistrationInput) (*RegistrationOptions, error)
	FinishRegistration(ctx context.Context, in FinishRegistrationInput) (*Passkey, error)

	// Ceremony: Authentication (User-specified or Discoverable)
	BeginAuthentication(ctx context.Context, in BeginAuthenticationInput) (*AuthenticationOptions, error)
	FinishAuthentication(ctx context.Context, in FinishAuthenticationInput) (*auth.AuthResult, error)

	// Management
	ListCredentials(ctx context.Context, userID string) ([]*Passkey, error)
	GetCredential(ctx context.Context, userID string, credentialID []byte) (*Passkey, error)
	UpdateCredential(ctx context.Context, in UpdateCredentialInput) (*Passkey, error)
	DeleteCredential(ctx context.Context, in DeleteCredentialInput) error
}
```

---

## Transport Integration Example (HTTP Handlers)

Because `Passkeys` takes byte slices and readers, creating HTTP handlers is straightforward:

```go
// 1. Begin Registration Handler
func HandleBeginRegistration(w http.ResponseWriter, r *http.Request, pk passkey.Passkeys, userID string) {
	opts, err := pk.BeginRegistration(r.Context(), passkey.BeginRegistrationInput{
		UserID:       userID,
		FriendlyName: "Work Laptop",
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	json.NewEncoder(w).Encode(opts)
}

// 2. Finish Registration Handler
func HandleFinishRegistration(w http.ResponseWriter, r *http.Request, pk passkey.Passkeys) {
	var req struct {
		SessionID string          `json:"session_id"`
		Response  json.RawMessage `json:"response"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	cred, err := pk.FinishRegistration(r.Context(), passkey.FinishRegistrationInput{
		SessionID: req.SessionID,
		Response:  req.Response,
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}
	json.NewEncoder(w).Encode(cred)
}

// 3. Begin Authentication Handler (Discoverable / Usernameless)
func HandleBeginAuthentication(w http.ResponseWriter, r *http.Request, pk passkey.Passkeys) {
	opts, err := pk.BeginAuthentication(r.Context(), passkey.BeginAuthenticationInput{})
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(opts)
}

// 4. Finish Authentication Handler
func HandleFinishAuthentication(w http.ResponseWriter, r *http.Request, pk passkey.Passkeys) {
	var req struct {
		SessionID string          `json:"session_id"`
		Response  json.RawMessage `json:"response"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	res, err := pk.FinishAuthentication(r.Context(), passkey.FinishAuthenticationInput{
		SessionID: req.SessionID,
		Response:  req.Response,
		Session: auth.SessionOptions{
			IPAddress: r.RemoteAddr,
			UserAgent: r.UserAgent(),
		},
	})
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// res.Token contains the session token to set as an HttpOnly cookie
	json.NewEncoder(w).Encode(map[string]any{
		"user":    res.User,
		"session": res.Session,
		"token":   res.Token,
	})
}
```

---

## Events

The plugin emits the following events through GoModularAuth's event bus:

| Event | Constant | Payload |
|---|---|---|
| `passkey.registered` | `passkey.EventPasskeyRegistered` | `PasskeyRegisteredPayload` (UserID, CredentialID, FriendlyName, AAGUID) |
| `passkey.used` | `passkey.EventPasskeyUsed` | `PasskeyUsedPayload` (UserID, CredentialID, SessionID, UsedAt) |
| `passkey.revoked` | `passkey.EventPasskeyRevoked` | `PasskeyRevokedPayload` (UserID, CredentialID, RevokedAt) |

No sensitive material (public keys, private keys, secrets, or challenges) is ever included in event payloads.

---

## Security Architecture

1. **Replay Protection**:
   - Every registration and login ceremony generates a cryptographically random challenge with a strictly enforced TTL.
   - Challenges are consumed **atomically** (`Consume`). Any attempt to re-use an already consumed challenge fails immediately with `ErrChallengeAlreadyUsed`.
2. **Sign Counter & Clone Detection**:
   - WebAuthn authenticators increment a 32-bit counter with each signature.
   - When `EnforceSignCounter` is active, any signature where the counter does not strictly increment from the stored counter (excluding multi-device sync keys returning 0) is flagged as cloned and rejected with `ErrSignCounterInvalid` or `ErrAuthenticatorCloned`.
3. **RP ID & Origin Validation**:
   - Configuration strictly validates that the RP ID is a valid domain or host without schemes or paths.
   - Origins must be fully qualified URLs (`https://...` or `http://localhost:...`). WebAuthn assertions against unexpected origins are rejected.
4. **Tenant & User Isolation**:
   - Management operations (`GetCredential`, `UpdateCredential`, `DeleteCredential`) enforce ownership matching against the caller's `UserID`, preventing horizontal privilege escalation.

---

## License

MIT License. See [LICENSE](LICENSE) for details.
