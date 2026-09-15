<p align="center">
  <img src="assets/logo.png" alt="Go Modular Auth Logo" width="200" />
</p>

<h1 align="center">Go Modular Auth</h1>

<p align="center">
  <strong>A modular, reactive, extensible, and strongly typed authentication framework for Go (Golang).</strong>
</p>

<p align="center">
  <a href="https://pkg.go.dev/github.com/BladiCreator/go-modular-auth"><img src="https://pkg.go.dev/badge/github.com/BladiCreator/go-modular-auth.svg" alt="Go Reference"></a>
  <a href="https://goreportcard.com/report/github.com/BladiCreator/go-modular-auth"><img src="https://goreportcard.com/badge/github.com/BladiCreator/go-modular-auth" alt="Go Report Card"></a>
  <a href="https://github.com/BladiCreator/go-modular-auth/releases/tag/v1.1.0"><img src="https://img.shields.io/badge/Release-v1.1.0-007EC6.svg" alt="Release: v1.1.0"></a>
  <a href="https://github.com/BladiCreator/go-modular-auth/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License: MIT"></a>
  <a href="https://golang.org/"><img src="https://img.shields.io/badge/Go-1.27+-00ADD8?logo=go" alt="Go Version"></a>
</p>

---

## 🌟 Overview

**Go Modular Auth** is a production-grade, highly extensible authentication and authorization engine for Go. Designed with clean architecture and maximum developer ergonomics, it allows developers to compose full-featured authentication systems from independent, pluggable modules (`emailpassword`, `twofactor`, `passkey`, `oauth2`, `jwt`, `organization`, `admin`, and 20+ more) without locking your codebase into any web framework.

It is 100% compatible with standard **`net/http`**, **Gin**, **Fiber**, **Echo**, **Chi**, or **gRPC** services.

---

## 🚀 Key Features

- 🧩 **25+ Pluggable Authentication Modules**: Add or remove credentials, multi-factor auth, social sign-ins, organizations, or payment entitlements as simple plug-and-play modules.
- 🔑 **Centralized Session Orchestration (`SessionManager`)**: Single source of truth for session lifecycles, sliding windows, remember-me durations, cryptographically hashed tokens, IP/User-Agent tracking, and multi-device revocation via `config.WithSessionRepository(store)`.
- 🛡️ **Polymorphic AuthResult & Step-Up Auth Engine (MFA)**: `SignIn` returns `*dto.AuthResult`, automatically issuing complete sessions or signed multi-factor challenges (`authRes.RequiresChallenge()`) without manual handler branching.
- 🔒 **Cryptographic Anti-Tampering & Anti-Replay Protection**: MFA challenge tokens (`mfa_<token>.<hmacSig>`) are signed using HMAC-SHA256 with strict 5-minute TTLs and atomic single-use invalidation upon verification.
- 📱 **Trusted Device Bypass**: Authorize verified devices (`TrustDevice=true`) to safely bypass 2FA challenges on subsequent logins.
- 🌐 **Standard HTTP Utilities (`httpauth` package)**: Pure `net/http` utilities for cookie management (`CookieManager`), Bearer token extraction, session resolution, and request context injection (`httpauth.WithSession`, `httpauth.SessionFromContext`).
- 📢 **Synchronous Pipeline & Typed Reactive Hooks**: Intercept in-flight parameters with `Pipeline()` (e.g. `ErrUserBanned`, `ErrTenantInactive`) and subscribe to typed lifecycle notifications with `Hooks()` (e.g. `OnUserSignedUp`, `EventSignInAfter`).
- ⚡ **Strong Typing with Generics (Go 1.18+)**: Access plugin APIs with zero casting and full IDE autocomplete via `auth.Plugin[P](app)`.
- 🗄️ **Decoupled Storage**: Bring your own database (**PostgreSQL**, **MySQL**, **SQLite**, **MongoDB**, **Redis**, **GORM**) through clean repository interfaces, or use the built-in thread-safe in-memory adapter.

---

## 📦 Installation

```bash
go get github.com/BladiCreator/go-modular-auth@v1.1.0
```

---

## 💡 Quickstart & Production Example

The following example demonstrates user registration, synchronous parameter interception, user sign-in with session emission, 2FA TOTP activation, MFA challenge interception, and challenge resolution:

```go
package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/BladiCreator/go-modular-auth/adapters/memory"
	"github.com/BladiCreator/go-modular-auth/auth"
	"github.com/BladiCreator/go-modular-auth/config"
	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/BladiCreator/go-modular-auth/plugins"
	"github.com/BladiCreator/go-modular-auth/plugins/emailpassword"
	"github.com/BladiCreator/go-modular-auth/plugins/twofactor"
)

func main() {
	ctx := context.Background()

	// 1. Storage adapter (shared in-memory repository for this example)
	storage := memory.New()

	// 2. Initialize the central Auth engine with SessionRepository and plugins
	app, err := auth.New(
		config.WithSessionRepository(storage),
		config.WithSessionConfig(auth.SessionConfig{
			DefaultDuration: 24 * time.Hour,
			RememberMeDuration: 30 * 24 * time.Hour,
		}),
		config.WithPlugins(
			plugins.EmailPassword(storage, emailpassword.WithMinPasswordLength(8)),
			plugins.TwoFactor(storage, twofactor.WithIssuer("My Secure App")),
		),
	)
	if err != nil {
		log.Fatalf("Failed to initialize Auth engine: %v", err)
	}

	// 3. Typed Lifecycle Hooks: Welcome email & audit log
	app.Hooks().OnUserSignedUp(func(c context.Context, user *entity.User) {
		fmt.Printf("📢 [Hook] Sending welcome email to: %s\n", user.Email)
	})

	app.Hooks().Subscribe(emailpassword.EventSignInAfter, func(c context.Context, p *emailpassword.SignInEventPayload) {
		fmt.Printf("🛡️ [Audit] Sign-in succeeded for: %s (ID: %s)\n", p.User.Email, p.User.ID)
	})

	// 4. Register a new user
	fmt.Println("--- 1. User Registration ---")
	epPlugin := auth.Plugin[emailpassword.Plugin](app)
	newUser, err := epPlugin.SignUp(ctx, dto.SignUpParams{
		Name:     "Gopher Developer",
		Email:    "gopher@golang.org",
		Password: "SecurePassword123!",
	})
	if err != nil {
		log.Fatalf("Sign up failed: %v", err)
	}
	fmt.Printf("✔ Registered User: %s (%s)\n\n", newUser.Name, newUser.ID)

	// 5. Initial Sign-In (before 2FA: returns active session immediately)
	fmt.Println("--- 2. Initial Sign-In (No MFA) ---")
	initialAuth, err := epPlugin.SignIn(ctx, dto.SignInParams{
		Email:    "gopher@golang.org",
		Password: "SecurePassword123!",
	})
	if err != nil {
		log.Fatalf("Sign in failed: %v", err)
	}

	if initialAuth.IsComplete() {
		fmt.Printf("✔ Authenticated: User=%s, Session Token=%s\n\n",
			initialAuth.User.Name, initialAuth.Session.Token)
	}

	// 6. Enroll and verify 2FA TOTP
	fmt.Println("--- 3. 2FA TOTP Enrollment ---")
	tfPlugin := auth.Plugin[twofactor.Plugin](app)
	enableRes, err := tfPlugin.Enable(ctx, twofactor.EnableParams{
		UserID: newUser.ID,
	})
	if err != nil {
		log.Fatalf("Enable 2FA failed: %v", err)
	}
	fmt.Printf("✔ 2FA Setup URI: %s\n", enableRes.TOTPURI)
	fmt.Printf("✔ Backup Codes: %v\n", enableRes.BackupCodes)

	// Generate current TOTP code and verify to activate 2FA
	totpCode, _ := twofactor.GenerateTOTPCode(enableRes.Secret, time.Now().Unix(), 30, 6, twofactor.AlgorithmSHA1)
	_, err = tfPlugin.VerifyTOTP(ctx, twofactor.VerifyTOTPParams{
		UserID: newUser.ID,
		Code:   totpCode,
	})
	if err != nil {
		log.Fatalf("2FA verification failed: %v", err)
	}
	fmt.Printf("✔ 2FA activated successfully!\n\n")

	// 7. Sign in with 2FA active (Step-Up Auth Challenge)
	fmt.Println("--- 4. Sign-In with 2FA Active (MFA Challenge) ---")
	mfaAuth, err := epPlugin.SignIn(ctx, dto.SignInParams{
		Email:    "gopher@golang.org",
		Password: "SecurePassword123!",
	})
	if err != nil {
		log.Fatalf("Sign in failed: %v", err)
	}

	if mfaAuth.RequiresChallenge() {
		fmt.Printf("⚠️ MFA Challenge Required: factor=%s, token=%s (Expires: %s)\n\n",
			mfaAuth.Challenge().FactorRequired,
			mfaAuth.Challenge().TempToken,
			mfaAuth.Challenge().ExpiresAt.Format(time.RFC3339))

		// 8. Resolve Challenge using the central Auth engine
		fmt.Println("--- 5. Challenge Resolution ---")
		freshTOTP, _ := twofactor.GenerateTOTPCode(enableRes.Secret, time.Now().Unix(), 30, 6, twofactor.AlgorithmSHA1)
		sessionData, err := app.VerifyTwoFactorChallenge(ctx, mfaAuth.Challenge().TempToken, freshTOTP)
		if err != nil {
			log.Fatalf("Challenge resolution failed: %v", err)
		}
		fmt.Printf("🎉 Final Session Issued: Token=%s (User: %s)\n",
			sessionData.Session.Token, sessionData.User.Name)
	}
}
```

---

## 🌐 HTTP Transport Integration (`httpauth` Package)

The `httpauth` package provides idiomatic, framework-agnostic utilities for standard `net/http` handlers and middlewares:

```go
package main

import (
	"net/http"

	"github.com/BladiCreator/go-modular-auth/auth"
	"github.com/BladiCreator/go-modular-auth/httpauth"
)

func RegisterHTTPRoutes(mux *http.ServeMux, app *auth.Auth) {
	// Protected handler reading authenticated session and user from context
	protectedEndpoint := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		session, ok := httpauth.SessionFromContext(r.Context())
		if !ok {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		w.Write([]byte("Hello, User: " + session.UserID))
	})

	// Middleware validating session token from cookies or Authorization Bearer header
	authMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, err := httpauth.ExtractToken(r, httpauth.WithExtractBearer())
			if err != nil || token == "" {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			sessionData, err := app.ValidateSession(r.Context(), token)
			if err != nil {
				httpauth.ClearSessionCookie(w)
				http.Error(w, "Session expired or invalid", http.StatusUnauthorized)
				return
			}

			ctx := httpauth.WithSessionData(r.Context(), sessionData)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}

	mux.Handle("/api/profile", authMiddleware(protectedEndpoint))
}
```

---

## 🛡️ Step-Up Auth & MFA Challenge Engine

When multi-factor authentication is active on an account, `SignIn` intercepts credential verification and produces a pending `dto.AuthChallenge`:

```go
authRes, err := epPlugin.SignIn(ctx, dto.SignInParams{
    Email:    "user@example.com",
    Password: "password123",
})
if err != nil {
    return err
}

if authRes.RequiresChallenge() {
    challenge := authRes.Challenge()
    // Respond with HTTP 428 Precondition Required or JSON containing challenge details:
    // { "mfa_required": true, "challenge_token": challenge.TempToken, "factor": challenge.FactorRequired }
    return nil
}

// 2FA not required: session is ready
session := authRes.Session
```

### Challenge Resolution
Clients submit their verification code (TOTP, backup code, or SMS/email OTP) alongside the signed challenge token:

```go
sessionData, err := app.VerifyChallenge(ctx, dto.VerifyChallengeParams{
    ChallengeToken: req.ChallengeToken,
    Code:           req.Code,
    Method:         "totp", // or "backup_code", "otp"
    TrustDevice:    req.RememberDevice,
    DeviceID:       req.DeviceID,
})
if err != nil {
    // ErrInvalidChallengeToken, ErrChallengeExpired, ErrInvalidCode, ErrAccountLocked
    return err
}

// Challenge solved: sessionData contains *entity.Session and *entity.User
```

### Trusted Device Bypass
By setting `TrustDevice: true` along with a unique `DeviceID`, a cryptographically signed device token is generated. On subsequent sign-ins, supplying `device_id` and `trust_device_token` via session options bypasses 2FA automatically:

```go
authRes, err := epPlugin.SignIn(ctx, dto.SignInParams{
    Email:    "user@example.com",
    Password: "password123",
}, auth.WithExtra("device_id", clientDeviceID), auth.WithExtra("trust_device_token", savedDeviceToken))
```

---

## 🗄️ Custom Repository Implementation (GORM + PostgreSQL / MySQL)

To connect your persistent database, implement the required repository interfaces. The central `SessionRepository` handles sessions, while each plugin defines its own minimal domain storage contract:

```go
package store

import (
	"context"
	"errors"
	"time"

	"github.com/BladiCreator/go-modular-auth/auth"
	"github.com/BladiCreator/go-modular-auth/domain"
	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/BladiCreator/go-modular-auth/plugins/emailpassword"
	"github.com/BladiCreator/go-modular-auth/plugins/twofactor"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// Compile-time interface checks
var (
	_ auth.SessionRepository   = (*GormAuthRepository)(nil)
	_ emailpassword.Repository = (*GormAuthRepository)(nil)
	_ twofactor.Repository     = (*GormAuthRepository)(nil)
)

// --- GORM ORM Models ---

type UserModel struct {
	ID            string    `gorm:"primaryKey;type:varchar(64)"`
	Name          string    `gorm:"not null"`
	Email         string    `gorm:"uniqueIndex;not null"`
	PasswordHash  string    `gorm:"not null"`
	EmailVerified bool      `gorm:"default:false"`
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

type SessionModel struct {
	ID        string    `gorm:"primaryKey;type:varchar(64)"`
	UserID    string    `gorm:"index;not null"`
	Token     string    `gorm:"uniqueIndex;not null"`
	IPAddress string
	UserAgent string
	ExpiresAt time.Time `gorm:"index"`
	CreatedAt time.Time
}

type TwoFactorModel struct {
	ID          string     `gorm:"primaryKey;type:varchar(64)"`
	UserID      string     `gorm:"uniqueIndex;not null"`
	Secret      string     `gorm:"not null"`
	BackupCodes string     `gorm:"type:text"`
	Verified    bool       `gorm:"default:false"`
	Failures    int        `gorm:"default:0"`
	LockedUntil *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

type ChallengeModel struct {
	Token          string    `gorm:"primaryKey;type:varchar(128)"`
	ID             string    `gorm:"index;not null"`
	UserID         string    `gorm:"index;not null"`
	FactorRequired string    `gorm:"not null"`
	Signature      string    `gorm:"not null"`
	ExpiresAt      time.Time `gorm:"index"`
	CreatedAt      time.Time
}

type TrustDeviceModel struct {
	ID        string    `gorm:"primaryKey;type:varchar(128)"`
	UserID    string    `gorm:"index;not null"`
	DeviceID  string    `gorm:"index;not null"`
	TokenHash string    `gorm:"not null"`
	ExpiresAt time.Time `gorm:"index"`
	CreatedAt time.Time
}

// --- Main Repository Struct ---

type GormAuthRepository struct {
	db *gorm.DB
}

func NewGormAuthRepository(db *gorm.DB) *GormAuthRepository {
	_ = db.AutoMigrate(
		&UserModel{},
		&SessionModel{},
		&TwoFactorModel{},
		&ChallengeModel{},
		&TrustDeviceModel{},
	)
	return &GormAuthRepository{db: db}
}

// --- auth.SessionRepository Implementation ---

func (r *GormAuthRepository) CreateSession(ctx context.Context, s *dto.CreateSessionParams) (*entity.Session, error) {
	model := SessionModel{
		ID:        uuid.New().String(),
		UserID:    s.UserID,
		Token:     s.Token,
		IPAddress: s.IPAddress,
		UserAgent: s.UserAgent,
		ExpiresAt: s.ExpiresAt,
		CreatedAt: s.CreatedAt,
	}
	if err := r.db.WithContext(ctx).Create(&model).Error; err != nil {
		return nil, err
	}
	return &entity.Session{
		ID: model.ID, UserID: model.UserID, Token: model.Token,
		IPAddress: model.IPAddress, UserAgent: model.UserAgent,
		ExpiresAt: model.ExpiresAt, CreatedAt: model.CreatedAt,
	}, nil
}

func (r *GormAuthRepository) GetSessionByToken(ctx context.Context, token string) (*entity.Session, error) {
	var model SessionModel
	err := r.db.WithContext(ctx).Where("token = ?", token).First(&model).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, domain.ErrSessionNotFound
	}
	return &entity.Session{
		ID: model.ID, UserID: model.UserID, Token: model.Token,
		IPAddress: model.IPAddress, UserAgent: model.UserAgent,
		ExpiresAt: model.ExpiresAt, CreatedAt: model.CreatedAt,
	}, err
}

func (r *GormAuthRepository) DeleteSession(ctx context.Context, token string) error {
	return r.db.WithContext(ctx).Where("token = ?", token).Delete(&SessionModel{}).Error
}

func (r *GormAuthRepository) DeleteSessionsByUserID(ctx context.Context, userID string) error {
	return r.db.WithContext(ctx).Where("user_id = ?", userID).Delete(&SessionModel{}).Error
}

// --- emailpassword.Repository Implementation ---

func (r *GormAuthRepository) CreateUser(ctx context.Context, p *dto.CreateUserParams) (*entity.User, error) {
	model := UserModel{
		ID:           uuid.New().String(),
		Name:         p.Name,
		Email:        p.Email,
		PasswordHash: p.PasswordHash,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
	if err := r.db.WithContext(ctx).Create(&model).Error; err != nil {
		return nil, err
	}
	return &entity.User{
		ID: model.ID, Name: model.Name, Email: model.Email,
		PasswordHash: model.PasswordHash, EmailVerified: model.EmailVerified,
		CreatedAt: model.CreatedAt, UpdatedAt: model.UpdatedAt,
	}, nil
}

func (r *GormAuthRepository) GetUserByEmail(ctx context.Context, email string) (*entity.User, error) {
	var m UserModel
	err := r.db.WithContext(ctx).Where("email = ?", email).First(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, domain.ErrUserNotFound
	}
	return &entity.User{
		ID: m.ID, Name: m.Name, Email: m.Email,
		PasswordHash: m.PasswordHash, EmailVerified: m.EmailVerified,
		CreatedAt: m.CreatedAt, UpdatedAt: m.UpdatedAt,
	}, err
}

func (r *GormAuthRepository) GetUserByID(ctx context.Context, id string) (*entity.User, error) {
	var m UserModel
	err := r.db.WithContext(ctx).Where("id = ?", id).First(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, domain.ErrUserNotFound
	}
	return &entity.User{
		ID: m.ID, Name: m.Name, Email: m.Email,
		PasswordHash: m.PasswordHash, EmailVerified: m.EmailVerified,
		CreatedAt: m.CreatedAt, UpdatedAt: m.UpdatedAt,
	}, err
}

func (r *GormAuthRepository) UpdateUser(ctx context.Context, u *entity.User) error {
	return r.db.WithContext(ctx).Model(&UserModel{}).Where("id = ?", u.ID).Updates(map[string]any{
		"name":           u.Name,
		"email":          u.Email,
		"password_hash":  u.PasswordHash,
		"email_verified": u.EmailVerified,
		"updated_at":     time.Now(),
	}).Error
}

func (r *GormAuthRepository) GetAccountByUserIDAndProvider(ctx context.Context, userID, provider string) (*dto.AccountData, error) {
	var m UserModel
	err := r.db.WithContext(ctx).Where("id = ?", userID).First(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &dto.AccountData{
		UserID:   m.ID,
		Provider: provider,
		Password: m.PasswordHash,
	}, err
}

func (r *GormAuthRepository) CreateAccount(ctx context.Context, p *dto.CreateAccountParams) error {
	return nil // Merged into UserModel in this single-table example
}

func (r *GormAuthRepository) UpdateAccountPassword(ctx context.Context, userID, newHash string) error {
	return r.db.WithContext(ctx).Model(&UserModel{}).Where("id = ?", userID).Update("password_hash", newHash).Error
}

// --- twofactor.Repository Implementation ---

func (r *GormAuthRepository) FindByUserID(ctx context.Context, userID string) (*twofactor.TwoFactor, error) {
	var m TwoFactorModel
	err := r.db.WithContext(ctx).Where("user_id = ?", userID).First(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, twofactor.ErrTwoFactorNotEnabled
	}
	return &twofactor.TwoFactor{
		ID: m.ID, UserID: m.UserID, Secret: m.Secret,
		BackupCodes: m.BackupCodes, Verified: m.Verified, Failures: m.Failures,
		LockedUntil: m.LockedUntil, CreatedAt: m.CreatedAt, UpdatedAt: m.UpdatedAt,
	}, err
}

func (r *GormAuthRepository) Save(ctx context.Context, tf *twofactor.TwoFactor) error {
	var existing TwoFactorModel
	err := r.db.WithContext(ctx).Where("user_id = ?", tf.UserID).First(&existing).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		m := TwoFactorModel{
			ID: uuid.New().String(), UserID: tf.UserID, Secret: tf.Secret,
			BackupCodes: tf.BackupCodes, Verified: tf.Verified, Failures: tf.Failures,
			LockedUntil: tf.LockedUntil, CreatedAt: time.Now(), UpdatedAt: time.Now(),
		}
		return r.db.WithContext(ctx).Create(&m).Error
	}
	return r.db.WithContext(ctx).Model(&TwoFactorModel{}).Where("user_id = ?", tf.UserID).Updates(map[string]any{
		"secret": tf.Secret, "backup_codes": tf.BackupCodes, "verified": tf.Verified,
		"failures": tf.Failures, "locked_until": tf.LockedUntil, "updated_at": time.Now(),
	}).Error
}

func (r *GormAuthRepository) Update(ctx context.Context, tf *twofactor.TwoFactor) error {
	return r.Save(ctx, tf)
}

func (r *GormAuthRepository) DeleteByUserID(ctx context.Context, userID string) error {
	return r.db.WithContext(ctx).Where("user_id = ?", userID).Delete(&TwoFactorModel{}).Error
}

func (r *GormAuthRepository) SaveChallenge(ctx context.Context, ch *twofactor.ChallengeRecord) error {
	m := ChallengeModel{
		Token: ch.Token, ID: ch.ID, UserID: ch.UserID,
		FactorRequired: ch.FactorRequired, Signature: ch.Signature,
		ExpiresAt: ch.ExpiresAt, CreatedAt: ch.CreatedAt,
	}
	return r.db.WithContext(ctx).Save(&m).Error
}

func (r *GormAuthRepository) GetChallenge(ctx context.Context, token string) (*twofactor.ChallengeRecord, error) {
	var m ChallengeModel
	err := r.db.WithContext(ctx).Where("token = ?", token).First(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &twofactor.ChallengeRecord{
		Token: m.Token, ID: m.ID, UserID: m.UserID,
		FactorRequired: m.FactorRequired, Signature: m.Signature,
		ExpiresAt: m.ExpiresAt, CreatedAt: m.CreatedAt,
	}, err
}

func (r *GormAuthRepository) DeleteChallenge(ctx context.Context, token string) error {
	return r.db.WithContext(ctx).Where("token = ?", token).Delete(&ChallengeModel{}).Error
}

func (r *GormAuthRepository) SaveTrustDevice(ctx context.Context, rec *twofactor.TrustDeviceRecord) error {
	m := TrustDeviceModel{
		ID: rec.ID, UserID: rec.UserID, DeviceID: rec.DeviceID,
		TokenHash: rec.TokenHash, ExpiresAt: rec.ExpiresAt, CreatedAt: rec.CreatedAt,
	}
	return r.db.WithContext(ctx).Save(&m).Error
}

func (r *GormAuthRepository) FindTrustDevice(ctx context.Context, userID, deviceID string) (*twofactor.TrustDeviceRecord, error) {
	var m TrustDeviceModel
	err := r.db.WithContext(ctx).Where("user_id = ? AND device_id = ?", userID, deviceID).First(&m).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	return &twofactor.TrustDeviceRecord{
		ID: m.ID, UserID: m.UserID, DeviceID: m.DeviceID,
		TokenHash: m.TokenHash, ExpiresAt: m.ExpiresAt, CreatedAt: m.CreatedAt,
	}, err
}

func (r *GormAuthRepository) DeleteTrustDevice(ctx context.Context, userID, deviceID string) error {
	return r.db.WithContext(ctx).Where("user_id = ? AND device_id = ?", userID, deviceID).Delete(&TrustDeviceModel{}).Error
}

func (r *GormAuthRepository) DeleteTrustDevicesByUserID(ctx context.Context, userID string) error {
	return r.db.WithContext(ctx).Where("user_id = ?", userID).Delete(&TrustDeviceModel{}).Error
}
```

---

## 📢 Synchronous Pipeline & Reactive Lifecycle Hooks

`go-modular-auth` provides a dual architecture that eliminates external message queues for local execution:

```
[In-Flight Request]
       │
       ▼
┌────────────────────────────────────────────────────────┐
│  app.Pipeline() [Synchronous Interceptor Chain]        │
│  - StageBeforeSignIn / StageBeforeSignUp               │
│  - In-flight mutation: input.Set("tenant_id", ...)     │
│  - Immediate abort: ErrUserBanned, ErrTenantInactive   │
└────────────────────────────────────────────────────────┘
       │
       ▼
[Database Persistence & Session Generation]
       │
       ▼
┌────────────────────────────────────────────────────────┐
│  app.Hooks() [Reactive Lifecycle Dispatcher]           │
│  - OnUserSignedUp / OnUserSignedIn                     │
│  - Typed subscriptions: EventSignInAfter, etc.         │
│  - Audit logs, metrics, notifications, welcome emails  │
└────────────────────────────────────────────────────────┘
```

### 1. Synchronous Guard Interceptors (`Pipeline().AddBeforeSignIn`)
```go
app.Pipeline().AddBeforeSignIn(func(ctx context.Context, input *dto.SignInParams) error {
    if isIPBlocked(ctx) {
        return domain.ErrUserBanned // Aborts execution immediately before touching database!
    }
    input.Set("audit_timestamp", time.Now().Unix())
    return nil
})
```

### 2. Typed Lifecycle Notifications (`Hooks().On*`)
```go
app.Hooks().OnUserSignedUp(func(ctx context.Context, user *entity.User) {
    go mailer.SendWelcomeEmail(user.Email, user.Name)
})
```

---

## 🔌 Available Plugins Directory

| Plugin | Factory Constructor | Category | Description |
| :--- | :--- | :--- | :--- |
| **`emailpassword`** | `plugins.EmailPassword(repo, opts...)` | Credentials | Traditional email/password sign-up, login, verification, and reset flows. |
| **`username`** | `plugins.Username(repo, opts...)` | Credentials | Username-based sign-in, username validation, and normalization. |
| **`phonenumber`** | `plugins.PhoneNumber(repo, opts...)` | Credentials | SMS OTP passwordless login, phone verification, and phone credential sign-in. |
| **`emailotp`** | `plugins.EmailOTP(repo, opts...)` | Passwordless | Email one-time password sign-in and verification. |
| **`magiclink`** | `plugins.MagicLink(repo, opts...)` | Passwordless | Passwordless magic link email generation, signing, and verification. |
| **`anonymous`** | `plugins.Anonymous(repo, opts...)` | Credentials | Guest and anonymous temporary account creation and conversion. |
| **`twofactor`** | `plugins.TwoFactor(repo, opts...)` | Multi-Factor | RFC 6238 TOTP, single-use backup codes, out-of-band OTPs, and trusted devices. |
| **`passkey`** | `plugins.Passkey(repo, opts...)` | Hardware / FIDO | WebAuthn FIDO2 biometric authentication and hardware security keys. |
| **`deviceauth`** | `plugins.DeviceAuth(repo, opts...)` | Hardware / IoT | RFC 8628 OAuth 2.0 device authorization grant for smart TVs and CLI tools. |
| **`bearer`** | `plugins.Bearer(opts...)` | Tokens | RFC 7235 Bearer token extraction, HMAC signing, and CORS headers. |
| **`jwt`** | `plugins.JWT(repo, opts...)` | Tokens | RFC 7519 JSON Web Token signing, verification, and RFC 7517 JWKS discovery. |
| **`customsession`** | `plugins.CustomSession(opts...)` | Sessions | Dynamic session metadata enrichment and custom context claims. |
| **`multisession`** | `plugins.MultiSession(repo, opts...)` | Sessions | Concurrent device session tracking, device limits, and selective logout. |
| **`ott`** | `plugins.OTT(repo, opts...)` | Tokens | Single-use One-Time Tokens for secure cross-service handoffs. |
| **`oauth2`** | `plugins.OAuth2(opts...)` | Federated | OAuth 2.0 authorization code flow with PKCE and state protection. |
| **`genericoauth`** | `plugins.GenericOAuth(opts...)` | Federated | Pre-configured social login providers (GitHub, Google, Discord, Microsoft, etc.). |
| **`oidcprovider`** | `plugins.OIDCProvider(repo, opts...)` | Enterprise | Full OpenID Connect identity provider implementation for federated auth. |
| **`oauthproxy`** | `plugins.OAuthProxy(opts...)` | Enterprise | Secure reverse proxy for centralized enterprise identity gateways. |
| **`admin`** | `plugins.Admin(repo, opts...)` | Enterprise | User impersonation, user ban/unban, and administrative management. |
| **`organization`** | `plugins.Organization(repo, opts...)` | Multi-Tenant | Multi-tenant organization accounts, team invitations, and role assignments. |
| **`access`** | `plugins.Access(repo, opts...)` | Authorization | Fine-grained Role-Based (RBAC) and Attribute-Based (ABAC) access control. |
| **`apikey`** | `plugins.APIKey(repo, opts...)` | API Security | Secret API keys for automated machines, service-to-service, and rate budgets. |
| **`captcha`** | `plugins.Captcha(opts...)` | Bot Defense | Turnstile, reCAPTCHA v2/v3, and hCaptcha bot protection. |
| **`lastloginmethod`**| `plugins.LastLoginMethod(repo, opts...)`| Intelligence | Remembers and recommends the user's preferred login mechanism. |
| **`stripe`** | `plugins.Stripe(opts...)` | Monetization | Webhook synchronization and subscription entitlement gating for Stripe. |
| **`polar`** | `plugins.Polar(opts...)` | Monetization | Webhook synchronization and customer tier entitlements for Polar.sh. |

---

## 📄 License

This project is licensed under the **MIT License**. See the [LICENSE](LICENSE) file for details.
