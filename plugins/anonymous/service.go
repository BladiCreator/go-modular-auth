package anonymous

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth-anonymous/cache"
	"github.com/BladiCreator/go-modular-auth-anonymous/store"
	"github.com/BladiCreator/go-modular-auth/account"
	"github.com/BladiCreator/go-modular-auth/credential"
	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
	corestore "github.com/BladiCreator/go-modular-auth/store"
	"github.com/BladiCreator/go-modular-auth/user"
)

type service struct {
	ctx   *sdk.Context
	cfg   Config
	store store.Store
	cache *cache.Cache
	hooks *Hooks
}

var _ Anonymous = (*service)(nil)

func newService(ctx *sdk.Context, cfg Config) *service {
	return &service{
		ctx:   ctx,
		cfg:   cfg,
		store: cfg.Store,
		cache: cache.New(ctx.Cache()),
		hooks: cfg.Hooks,
	}
}

// Authenticate creates a new Core User, links an anonymous account, persists an anonymous identity,
// and issues an authenticated session.
func (s *service) Authenticate(ctx context.Context, in AuthenticateInput) (*AuthResult, error) {
	if err := s.hooks.runBeforeCreate(ctx, &in); err != nil {
		return nil, err
	}

	now := s.ctx.Now()
	anonID, err := generateID()
	if err != nil {
		return nil, err
	}
	userID, err := generateID()
	if err != nil {
		return nil, err
	}
	accountID, err := generateID()
	if err != nil {
		return nil, err
	}

	syntheticEmail := fmt.Sprintf("anon_%s@%s", anonID, s.cfg.EmailDomain)
	expiresAt := now.Add(s.cfg.IdentityTTL)

	u := &user.User{
		ID:            userID,
		Email:         syntheticEmail,
		EmailVerified: false,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	acc := &account.Account{
		ID:         accountID,
		UserID:     userID,
		Provider:   ProviderAnonymous,
		ProviderID: anonID,
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	ident := &store.Identity{
		ID:        anonID,
		UserID:    userID,
		ExpiresAt: expiresAt,
		Metadata:  in.Metadata,
		CreatedAt: now,
		UpdatedAt: now,
	}

	var issuedSession *auth.IssuedSession

	err = s.ctx.Store().Transaction(ctx, func(txCtx context.Context) error {
		if err := s.ctx.Store().Users().Create(txCtx, u); err != nil {
			return fmt.Errorf("anonymous: create core user: %w", err)
		}
		if err := s.ctx.Store().Accounts().Create(txCtx, acc); err != nil {
			return fmt.Errorf("anonymous: create core account: %w", err)
		}
		if err := s.store.Create(txCtx, ident); err != nil {
			return fmt.Errorf("anonymous: create identity: %w", err)
		}

		var sessionErr error
		issuedSession, sessionErr = s.ctx.Core().CreateSession(txCtx, userID, in.Session)
		if sessionErr != nil {
			return fmt.Errorf("anonymous: create session: %w", sessionErr)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	_ = s.cache.SetIdentity(ctx, ident, s.cfg.CacheTTL)

	res := &AuthResult{
		User:     u,
		Session:  issuedSession.Session,
		Token:    issuedSession.Token,
		Identity: ident,
	}

	s.ctx.Events().Publish(ctx, auth.Event{
		Name:    EventAnonymousCreated,
		Time:    now,
		Subject: userID,
		Payload: CreatedPayload{
			IdentityID: ident.ID,
			UserID:     ident.UserID,
			ExpiresAt:  ident.ExpiresAt,
			CreatedAt:  ident.CreatedAt,
		},
	})

	s.hooks.runAfterCreate(ctx, res)
	return res, nil
}

// GetIdentity retrieves the anonymous identity associated with the given Core User ID.
func (s *service) GetIdentity(ctx context.Context, userID string) (*Identity, error) {
	if userID == "" {
		return nil, ErrAnonymousNotFound
	}

	if cached, err := s.cache.GetIdentity(ctx, userID); err == nil && cached != nil {
		return cached, nil
	}

	ident, err := s.store.GetByUserID(ctx, userID)
	if errors.Is(err, store.ErrNotFound) {
		return nil, ErrAnonymousNotFound
	}
	if err != nil {
		return nil, err
	}

	_ = s.cache.SetIdentity(ctx, ident, s.cfg.CacheTTL)
	return ident, nil
}

// IsAnonymous reports whether the given Core User ID corresponds to an active, unexpired,
// and unconverted anonymous identity.
func (s *service) IsAnonymous(ctx context.Context, userID string) (bool, error) {
	ident, err := s.GetIdentity(ctx, userID)
	if errors.Is(err, ErrAnonymousNotFound) {
		return false, nil
	}
	if err != nil {
		return false, err
	}

	now := s.ctx.Now()
	return ident.IsActive(now), nil
}

// Principal returns an auth.Principal for the given user ID:
// PrincipalAnonymous if actively anonymous, or auth.PrincipalUser if permanent/converted.
func (s *service) Principal(ctx context.Context, userID string) (auth.Principal, error) {
	isAnon, err := s.IsAnonymous(ctx, userID)
	if err != nil {
		return auth.Principal{}, err
	}
	if isAnon {
		return auth.Principal{Subject: userID, Type: PrincipalAnonymous}, nil
	}
	return auth.Principal{Subject: userID, Type: auth.PrincipalUser}, nil
}

// Convert converts an active anonymous user in-place to a permanent account with email and password.
func (s *service) Convert(ctx context.Context, in ConvertInput) (*ConvertResult, error) {
	if err := s.hooks.runBeforeConvert(ctx, &in); err != nil {
		return nil, err
	}

	userID := in.AnonymousUserID
	if in.AnonymousToken != "" {
		res, err := s.ctx.Core().GetSession(ctx, in.AnonymousToken)
		if err != nil {
			return nil, err
		}
		if res == nil {
			return nil, ErrInvalidAnonymousToken
		}
		if userID != "" && userID != res.User.ID {
			return nil, ErrInvalidAnonymousToken
		}
		userID = res.User.ID
	}

	if userID == "" {
		return nil, ErrUserNotAnonymous
	}

	normEmail, err := normalizeEmail(in.Email)
	if err != nil {
		return nil, ErrInvalidEmail
	}

	if len(in.Password) < s.cfg.MinPasswordLength || len(in.Password) > s.cfg.MaxPasswordLength {
		return nil, ErrInvalidPassword
	}

	// Verify email is not already claimed by an existing user
	existingUser, err := s.ctx.Store().Users().GetByEmail(ctx, normEmail)
	if err != nil && !errors.Is(err, corestore.ErrNotFound) {
		return nil, err
	}
	if existingUser != nil && existingUser.ID != userID {
		return nil, ErrUserAlreadyExists
	}

	ident, err := s.GetIdentity(ctx, userID)
	if err != nil {
		return nil, err
	}
	now := s.ctx.Now()
	if ident.Converted() {
		return nil, ErrAlreadyConverted
	}
	if ident.Expired(now) {
		return nil, ErrAnonymousExpired
	}

	// Hash password
	pwdHash, err := s.cfg.Hasher.Hash(ctx, in.Password)
	if err != nil {
		return nil, fmt.Errorf("anonymous: hash password: %w", err)
	}

	accountID, err := generateID()
	if err != nil {
		return nil, err
	}
	credentialID, err := generateID()
	if err != nil {
		return nil, err
	}

	var updatedUser *user.User

	err = s.ctx.Store().Transaction(ctx, func(txCtx context.Context) error {
		u, err := s.ctx.Store().Users().GetByID(txCtx, userID)
		if err != nil {
			return err
		}
		u.Email = normEmail
		u.UpdatedAt = now
		if err := s.ctx.Store().Users().Update(txCtx, u); err != nil {
			if errors.Is(err, corestore.ErrConflict) {
				return ErrUserAlreadyExists
			}
			return err
		}
		updatedUser = u

		// Link password provider account
		pwdAcc := &account.Account{
			ID:         accountID,
			UserID:     userID,
			Provider:   account.ProviderPassword,
			ProviderID: userID,
			CreatedAt:  now,
			UpdatedAt:  now,
		}
		if err := s.ctx.Store().Accounts().Create(txCtx, pwdAcc); err != nil && !errors.Is(err, corestore.ErrConflict) {
			return err
		}

		// Save password credential
		pwdCred := &credential.Credential{
			ID:        credentialID,
			UserID:    userID,
			AccountID: accountID,
			Type:      credential.TypePassword,
			Secret:    pwdHash,
			CreatedAt: now,
			UpdatedAt: now,
		}
		if err := s.ctx.Store().Credentials().Create(txCtx, pwdCred); err != nil {
			return err
		}

		// Update identity record
		ident.ConvertedAt = &now
		ident.UpdatedAt = now
		if err := s.store.Update(txCtx, ident); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	_ = s.cache.DeleteIdentity(ctx, userID)

	res := &ConvertResult{
		User:     updatedUser,
		Identity: ident,
	}

	s.ctx.Events().Publish(ctx, auth.Event{
		Name:    EventAnonymousConverted,
		Time:    now,
		Subject: userID,
		Payload: ConvertedPayload{
			IdentityID:  ident.ID,
			UserID:      userID,
			Provider:    account.ProviderPassword,
			ConvertedAt: now,
		},
	})

	s.hooks.runAfterConvert(ctx, res)
	return res, nil
}

// ConvertWithAccount converts an active anonymous user by linking an external provider account (e.g. OAuth, passkey).
func (s *service) ConvertWithAccount(ctx context.Context, in ConvertAccountInput) (*ConvertResult, error) {
	if in.Provider == "" {
		return nil, ErrProviderRequired
	}
	if in.ProviderID == "" {
		return nil, ErrProviderIDRequired
	}

	userID := in.AnonymousUserID
	if in.AnonymousToken != "" {
		res, err := s.ctx.Core().GetSession(ctx, in.AnonymousToken)
		if err != nil {
			return nil, err
		}
		if res == nil {
			return nil, ErrInvalidAnonymousToken
		}
		if userID != "" && userID != res.User.ID {
			return nil, ErrInvalidAnonymousToken
		}
		userID = res.User.ID
	}

	if userID == "" {
		return nil, ErrUserNotAnonymous
	}

	ident, err := s.GetIdentity(ctx, userID)
	if err != nil {
		return nil, err
	}
	now := s.ctx.Now()
	if ident.Converted() {
		return nil, ErrAlreadyConverted
	}
	if ident.Expired(now) {
		return nil, ErrAnonymousExpired
	}

	accountID, err := generateID()
	if err != nil {
		return nil, err
	}

	var updatedUser *user.User

	err = s.ctx.Store().Transaction(ctx, func(txCtx context.Context) error {
		u, err := s.ctx.Store().Users().GetByID(txCtx, userID)
		if err != nil {
			return err
		}

		if in.Email != "" {
			normEmail, err := normalizeEmail(in.Email)
			if err != nil {
				return ErrInvalidEmail
			}
			u.Email = normEmail
			u.UpdatedAt = now
			if err := s.ctx.Store().Users().Update(txCtx, u); err != nil {
				if errors.Is(err, corestore.ErrConflict) {
					return ErrUserAlreadyExists
				}
				return err
			}
		}
		updatedUser = u

		acc := &account.Account{
			ID:         accountID,
			UserID:     userID,
			Provider:   in.Provider,
			ProviderID: in.ProviderID,
			CreatedAt:  now,
			UpdatedAt:  now,
		}
		if err := s.ctx.Store().Accounts().Create(txCtx, acc); err != nil {
			return err
		}

		ident.ConvertedAt = &now
		ident.UpdatedAt = now
		if err := s.store.Update(txCtx, ident); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	_ = s.cache.DeleteIdentity(ctx, userID)

	res := &ConvertResult{
		User:     updatedUser,
		Identity: ident,
	}

	s.ctx.Events().Publish(ctx, auth.Event{
		Name:    EventAnonymousConverted,
		Time:    now,
		Subject: userID,
		Payload: ConvertedPayload{
			IdentityID:  ident.ID,
			UserID:      userID,
			Provider:    in.Provider,
			ConvertedAt: now,
		},
	})

	return res, nil
}

// Link merges an anonymous identity into an existing permanent account after validating explicit authentication
// for the permanent user.
func (s *service) Link(ctx context.Context, in LinkInput) (*LinkResult, error) {
	if err := s.hooks.runBeforeLink(ctx, &in); err != nil {
		return nil, err
	}

	anonUserID := in.AnonymousUserID
	if in.AnonymousToken != "" {
		sessRes, err := s.ctx.Core().GetSession(ctx, in.AnonymousToken)
		if err != nil {
			return nil, err
		}
		if sessRes == nil {
			return nil, ErrInvalidAnonymousToken
		}
		if anonUserID != "" && anonUserID != sessRes.User.ID {
			return nil, ErrInvalidAnonymousToken
		}
		anonUserID = sessRes.User.ID
	}

	if anonUserID == "" {
		return nil, ErrUserNotAnonymous
	}

	ident, err := s.GetIdentity(ctx, anonUserID)
	if err != nil {
		return nil, err
	}
	now := s.ctx.Now()
	if ident.Converted() {
		return nil, ErrAlreadyConverted
	}
	if ident.Expired(now) {
		return nil, ErrAnonymousExpired
	}

	// Authenticate the target permanent account
	var permUser *user.User

	if in.PermanentToken != "" {
		sessRes, err := s.ctx.Core().GetSession(ctx, in.PermanentToken)
		if err != nil {
			return nil, err
		}
		if sessRes == nil {
			return nil, ErrInvalidCredentials
		}
		permUser = sessRes.User
	} else if in.PermanentEmail != "" && in.PermanentPassword != "" {
		normEmail, err := normalizeEmail(in.PermanentEmail)
		if err != nil {
			return nil, ErrInvalidCredentials
		}
		u, err := s.ctx.Store().Users().GetByEmail(ctx, normEmail)
		if err != nil {
			if errors.Is(err, corestore.ErrNotFound) {
				return nil, ErrInvalidCredentials
			}
			return nil, err
		}

		acc, err := s.ctx.Store().Accounts().GetByProvider(ctx, account.ProviderPassword, u.ID)
		if err != nil {
			return nil, ErrInvalidCredentials
		}
		cred, err := s.ctx.Store().Credentials().GetActiveByAccount(ctx, acc.ID, credential.TypePassword)
		if err != nil {
			return nil, ErrInvalidCredentials
		}
		if err := s.cfg.Hasher.Verify(ctx, cred.Secret, in.PermanentPassword); err != nil {
			return nil, ErrInvalidCredentials
		}
		permUser = u
	} else {
		return nil, ErrInvalidCredentials
	}

	if permUser.ID == anonUserID {
		return nil, ErrSameAccount
	}

	// Prevent privilege escalation: Target must not be another anonymous user
	isTargetAnon, err := s.IsAnonymous(ctx, permUser.ID)
	if err != nil {
		return nil, err
	}
	if isTargetAnon {
		return nil, ErrTargetIsAnonymous
	}

	err = s.ctx.Store().Transaction(ctx, func(txCtx context.Context) error {
		ident.ConvertedAt = &now
		ident.LinkedUserID = permUser.ID
		ident.UpdatedAt = now
		if err := s.store.Update(txCtx, ident); err != nil {
			return err
		}

		if in.RevokeAnonymousSessions {
			_ = s.ctx.Core().RevokeUserSessions(txCtx, anonUserID, "")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	_ = s.cache.DeleteIdentity(ctx, anonUserID)

	res := &LinkResult{
		AnonymousUserID: anonUserID,
		PermanentUser:   permUser,
		Identity:        ident,
	}

	s.ctx.Events().Publish(ctx, auth.Event{
		Name:    EventAnonymousLinked,
		Time:    now,
		Subject: anonUserID,
		Payload: LinkedPayload{
			IdentityID:      ident.ID,
			AnonymousUserID: anonUserID,
			PermanentUserID: permUser.ID,
			LinkedAt:        now,
		},
	})

	s.hooks.runAfterLink(ctx, res)
	return res, nil
}

// Cleanup deletes expired and unconverted anonymous identities and their associated core users and sessions.
func (s *service) Cleanup(ctx context.Context, before time.Time) (CleanupResult, error) {
	if before.IsZero() {
		before = s.ctx.Now()
	}

	hookIn := CleanupInput{BeforeThreshold: before.Format(time.RFC3339)}
	if err := s.hooks.runBeforeCleanup(ctx, &hookIn); err != nil {
		return CleanupResult{}, err
	}

	// Batch list expired unconverted identities
	expiredList, err := s.store.ListExpired(ctx, before, 500)
	if err != nil {
		return CleanupResult{}, fmt.Errorf("anonymous: list expired: %w", err)
	}

	var result CleanupResult

	for _, ident := range expiredList {
		err := s.ctx.Store().Transaction(ctx, func(txCtx context.Context) error {
			// Revoke sessions
			if err := s.ctx.Core().RevokeUserSessions(txCtx, ident.UserID, ""); err == nil {
				result.SessionsRevoked++
			}

			// Delete core accounts linked to this anonymous identity
			accounts, _ := s.ctx.Store().Accounts().ListByUser(txCtx, ident.UserID)
			for _, acc := range accounts {
				_ = s.ctx.Store().Accounts().Delete(txCtx, acc.ID)
			}

			// Delete core user
			if err := s.ctx.Store().Users().Delete(txCtx, ident.UserID); err == nil {
				result.UsersDeleted++
			}

			// Delete anonymous identity
			if err := s.store.Delete(txCtx, ident.ID); err != nil {
				return err
			}
			result.IdentitiesDeleted++
			return nil
		})
		if err != nil {
			s.ctx.Logger().ErrorContext(ctx, "anonymous: cleanup record failed", "identity_id", ident.ID, "error", err)
			continue
		}
		_ = s.cache.DeleteIdentity(ctx, ident.UserID)
	}

	s.ctx.Events().Publish(ctx, auth.Event{
		Name:    EventAnonymousCleanedUp,
		Time:    s.ctx.Now(),
		Subject: "system",
		Payload: CleanedUpPayload{
			IdentitiesDeleted: result.IdentitiesDeleted,
			UsersDeleted:      result.UsersDeleted,
			SessionsRevoked:   result.SessionsRevoked,
			CleanedAt:         s.ctx.Now(),
		},
	})

	s.hooks.runAfterCleanup(ctx, &result)
	return result, nil
}

func generateID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func normalizeEmail(email string) (string, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return "", ErrInvalidEmail
	}
	addr, err := mail.ParseAddress(email)
	if err != nil || addr.Address != email || addr.Name != "" {
		return "", ErrInvalidEmail
	}
	return email, nil
}
