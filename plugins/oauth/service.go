package oauth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth/account"
	"github.com/BladiCreator/go-modular-auth/adapter"
	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
	"github.com/BladiCreator/go-modular-auth/plugins/oauth/provider"
	corestore "github.com/BladiCreator/go-modular-auth/store"
	"github.com/BladiCreator/go-modular-auth/user"
)

type service struct {
	ctx       *sdk.Context
	cfg       Config
	states    *sdk.Repository[StateSession]
	providers map[string]provider.Provider
	hooks     *Hooks
}

var _ OAuth = (*service)(nil)

func newService(ctx *sdk.Context, cfg Config) *service {
	return &service{
		ctx:       ctx,
		cfg:       cfg,
		states:    sdk.Model[StateSession](ctx, ModelOAuthStates),
		providers: cfg.Providers,
		hooks:     cfg.Hooks,
	}
}

func (s *service) consumeState(ctx context.Context, state string, now time.Time) (*StateSession, error) {
	if state == "" {
		return nil, ErrStateNotFound
	}
	sess, err := s.states.FindOne(ctx, adapter.Eq("state", state))
	if errors.Is(err, adapter.ErrNotFound) || sess == nil {
		return nil, ErrStateNotFound
	}
	if err != nil {
		return nil, err
	}
	if sess.Consumed() {
		return nil, ErrStateAlreadyConsumed
	}
	if sess.Expired(now) {
		return nil, ErrStateExpired
	}
	sess.ConsumedAt = &now
	_, err = s.states.Update(ctx, []adapter.Condition{adapter.Eq("state", state)}, map[string]any{
		"consumed_at": now,
	})
	if err != nil {
		return nil, err
	}
	return sess, nil
}

func (s *service) now() time.Time {
	if s.ctx != nil {
		return s.ctx.Now()
	}
	return time.Now()
}

func (s *service) publish(ctx context.Context, name auth.EventName, subject string, payload any) {
	if s.ctx != nil && s.ctx.Events() != nil {
		s.ctx.Events().Publish(ctx, auth.Event{
			Name:    name,
			Time:    s.now(),
			Subject: subject,
			Payload: payload,
		})
	}
}

// BeginAuth initiates an authorization code flow for authentication or sign up.
func (s *service) BeginAuth(ctx context.Context, in BeginAuthInput) (*BeginAuthResult, error) {
	if in.Provider == "" || in.RedirectURI == "" {
		return nil, fmt.Errorf("%w: provider and redirect_uri are required", ErrInvalidInput)
	}

	p, ok := s.providers[in.Provider]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrProviderNotFound, in.Provider)
	}

	if !p.ValidateRedirectURI(in.RedirectURI) {
		return nil, fmt.Errorf("%w: redirect URI %q is not allowed for provider %q", ErrInvalidRedirectURI, in.RedirectURI, in.Provider)
	}

	if err := s.hooks.runBeforeOAuthRedirect(ctx, &in); err != nil {
		return nil, err
	}

	state, err := generateRandomToken(32)
	if err != nil {
		return nil, fmt.Errorf("oauth: failed to generate state: %w", err)
	}

	usePKCE := s.cfg.UsePKCE
	if in.UsePKCE != nil {
		usePKCE = *in.UsePKCE
	}

	var (
		codeVerifier  string
		codeChallenge string
		codeMethod    string
	)

	if usePKCE {
		pkce, err := GeneratePKCE()
		if err != nil {
			return nil, fmt.Errorf("oauth: failed to generate pkce: %w", err)
		}
		codeVerifier = pkce.Verifier
		codeChallenge = pkce.Challenge
		codeMethod = pkce.Method
	}

	now := s.now()
	expiresAt := now.Add(s.cfg.StateTTL)

	stateSess := &StateSession{
		State:        state,
		Provider:     in.Provider,
		RedirectURI:  in.RedirectURI,
		CodeVerifier: codeVerifier,
		Action:       ActionSignIn,
		Metadata:     in.Metadata,
		ExpiresAt:    expiresAt,
		CreatedAt:    now,
	}

	if err := s.states.Create(ctx, stateSess); err != nil {
		return nil, fmt.Errorf("oauth: failed to save state session: %w", err)
	}

	opts := []provider.AuthCodeOption{
		provider.WithRedirectURI(in.RedirectURI),
	}
	if len(in.Scopes) > 0 {
		opts = append(opts, provider.WithScopes(in.Scopes...))
	}
	if codeChallenge != "" {
		opts = append(opts, provider.WithPKCE(codeChallenge, codeMethod))
	}
	if in.Prompt != "" {
		opts = append(opts, provider.WithPrompt(in.Prompt))
	}
	if in.AccessType != "" {
		opts = append(opts, provider.WithAccessType(in.AccessType))
	}

	authURL := p.AuthCodeURL(state, opts...)

	s.publish(ctx, EventOAuthStateCreated, state, StateCreatedPayload{
		Provider:  in.Provider,
		State:     state,
		Action:    string(ActionSignIn),
		ExpiresAt: expiresAt,
	})

	return &BeginAuthResult{
		AuthURL:      authURL,
		State:        state,
		CodeVerifier: codeVerifier,
		ExpiresAt:    expiresAt,
	}, nil
}

// BeginLink initiates an OAuth authorization code flow specifically for linking a provider to an existing authenticated user.
func (s *service) BeginLink(ctx context.Context, in BeginLinkInput) (*BeginAuthResult, error) {
	if in.UserID == "" || in.Provider == "" || in.RedirectURI == "" {
		return nil, fmt.Errorf("%w: user_id, provider and redirect_uri are required", ErrInvalidInput)
	}

	// Verify user exists in Core
	if _, err := s.ctx.Core().RequireUser(ctx, in.UserID); err != nil {
		return nil, err
	}

	p, ok := s.providers[in.Provider]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrProviderNotFound, in.Provider)
	}

	if !p.ValidateRedirectURI(in.RedirectURI) {
		return nil, fmt.Errorf("%w: redirect URI %q is not allowed for provider %q", ErrInvalidRedirectURI, in.RedirectURI, in.Provider)
	}

	beginInput := BeginAuthInput{
		Provider:    in.Provider,
		RedirectURI: in.RedirectURI,
		Scopes:      in.Scopes,
		Prompt:      in.Prompt,
		AccessType:  in.AccessType,
		Metadata:    in.Metadata,
		UsePKCE:     in.UsePKCE,
	}
	if err := s.hooks.runBeforeOAuthRedirect(ctx, &beginInput); err != nil {
		return nil, err
	}

	state, err := generateRandomToken(32)
	if err != nil {
		return nil, fmt.Errorf("oauth: failed to generate state: %w", err)
	}

	usePKCE := s.cfg.UsePKCE
	if in.UsePKCE != nil {
		usePKCE = *in.UsePKCE
	}

	var (
		codeVerifier  string
		codeChallenge string
		codeMethod    string
	)

	if usePKCE {
		pkce, err := GeneratePKCE()
		if err != nil {
			return nil, fmt.Errorf("oauth: failed to generate pkce: %w", err)
		}
		codeVerifier = pkce.Verifier
		codeChallenge = pkce.Challenge
		codeMethod = pkce.Method
	}

	now := s.now()
	expiresAt := now.Add(s.cfg.StateTTL)

	stateSess := &StateSession{
		State:        state,
		Provider:     in.Provider,
		RedirectURI:  in.RedirectURI,
		CodeVerifier: codeVerifier,
		Action:       ActionLink,
		UserID:       in.UserID,
		Metadata:     in.Metadata,
		ExpiresAt:    expiresAt,
		CreatedAt:    now,
	}

	if err := s.states.Create(ctx, stateSess); err != nil {
		return nil, fmt.Errorf("oauth: failed to save state session: %w", err)
	}

	opts := []provider.AuthCodeOption{
		provider.WithRedirectURI(in.RedirectURI),
	}
	if len(in.Scopes) > 0 {
		opts = append(opts, provider.WithScopes(in.Scopes...))
	}
	if codeChallenge != "" {
		opts = append(opts, provider.WithPKCE(codeChallenge, codeMethod))
	}
	if in.Prompt != "" {
		opts = append(opts, provider.WithPrompt(in.Prompt))
	}
	if in.AccessType != "" {
		opts = append(opts, provider.WithAccessType(in.AccessType))
	}

	authURL := p.AuthCodeURL(state, opts...)

	s.publish(ctx, EventOAuthStateCreated, state, StateCreatedPayload{
		Provider:  in.Provider,
		State:     state,
		Action:    string(ActionLink),
		UserID:    in.UserID,
		ExpiresAt: expiresAt,
	})

	return &BeginAuthResult{
		AuthURL:      authURL,
		State:        state,
		CodeVerifier: codeVerifier,
		ExpiresAt:    expiresAt,
	}, nil
}

// CompleteAuth completes an authorization code flow for authentication or account creation.
func (s *service) CompleteAuth(ctx context.Context, in CompleteAuthInput) (*AuthResult, error) {
	if in.Provider == "" || in.Code == "" || in.State == "" || in.RedirectURI == "" {
		return nil, fmt.Errorf("%w: provider, code, state and redirect_uri are required", ErrInvalidInput)
	}

	p, ok := s.providers[in.Provider]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrProviderNotFound, in.Provider)
	}

	now := s.now()
	stateSess, err := s.consumeState(ctx, in.State, now)
	if err != nil {
		s.publish(ctx, EventOAuthFailed, in.Provider, FailedPayload{Provider: in.Provider, Reason: "state_consumption_failed"})
		return nil, err
	}

	if stateSess.Provider != in.Provider {
		s.publish(ctx, EventOAuthFailed, in.Provider, FailedPayload{Provider: in.Provider, Reason: "provider_mismatch"})
		return nil, ErrInvalidState
	}

	if stateSess.Action != ActionSignIn {
		s.publish(ctx, EventOAuthFailed, in.Provider, FailedPayload{Provider: in.Provider, Reason: "action_mismatch"})
		return nil, fmt.Errorf("%w: expected sign_in, got %s", ErrInvalidAction, stateSess.Action)
	}

	if stateSess.RedirectURI != in.RedirectURI {
		s.publish(ctx, EventOAuthFailed, in.Provider, FailedPayload{Provider: in.Provider, Reason: "redirect_uri_mismatch"})
		return nil, fmt.Errorf("%w: expected %q, got %q", ErrInvalidRedirectURI, stateSess.RedirectURI, in.RedirectURI)
	}

	if err := s.hooks.runBeforeTokenExchange(ctx, in.Provider, in.Code); err != nil {
		return nil, err
	}

	exchangeOpts := []provider.ExchangeOption{
		provider.WithExchangeRedirectURI(in.RedirectURI),
	}
	if stateSess.CodeVerifier != "" {
		exchangeOpts = append(exchangeOpts, provider.WithCodeVerifier(stateSess.CodeVerifier))
	}

	tokenResp, err := p.Exchange(ctx, in.Code, exchangeOpts...)
	if err != nil {
		s.publish(ctx, EventOAuthFailed, in.Provider, FailedPayload{Provider: in.Provider, Reason: "exchange_failed"})
		return nil, fmt.Errorf("%w: %v", ErrTokenExchangeFailed, err)
	}

	profile, err := p.FetchProfile(ctx, tokenResp)
	if err != nil {
		s.publish(ctx, EventOAuthFailed, in.Provider, FailedPayload{Provider: in.Provider, Reason: "profile_fetch_failed"})
		return nil, fmt.Errorf("%w: %v", ErrProfileFetchFailed, err)
	}

	if profile.ProviderID == "" {
		return nil, ErrInvalidProfile
	}

	if err := s.hooks.runAfterProfileFetched(ctx, profile); err != nil {
		return nil, err
	}

	// 1. Check if an account already exists for (Provider, ProviderID)
	acc, err := s.ctx.Store().Accounts().GetByProvider(ctx, in.Provider, profile.ProviderID)
	if err != nil && !errors.Is(err, corestore.ErrNotFound) {
		return nil, fmt.Errorf("oauth: lookup account: %w", err)
	}

	if acc != nil {
		// Existing account found: Authenticate user directly
		u, err := s.ctx.Core().GetUser(ctx, acc.UserID)
		if err != nil {
			return nil, fmt.Errorf("oauth: get user: %w", err)
		}
		if u == nil {
			return nil, auth.ErrUserNotFound
		}

		issued, err := s.ctx.Core().CreateSession(ctx, u.ID, in.Session)
		if err != nil {
			return nil, fmt.Errorf("oauth: create session: %w", err)
		}

		result := &AuthResult{
			User:          u,
			Account:       acc,
			Session:       issued.Session,
			Token:         issued.Token,
			IsNewUser:     false,
			TokenResponse: tokenResp,
			Profile:       profile,
		}

		s.publish(ctx, EventOAuthAuthenticated, u.ID, AuthenticatedPayload{
			UserID:     u.ID,
			AccountID:  acc.ID,
			Provider:   in.Provider,
			ProviderID: profile.ProviderID,
			IsNewUser:  false,
		})

		_ = s.hooks.runAfterOAuthSignIn(ctx, result)
		return result, nil
	}

	// 2. Account does not exist. Check if an existing user has the same email.
	var normalizedEmail string
	if profile.Email != "" {
		normalizedEmail, _ = user.NormalizeEmail(profile.Email)
	}

	var existingUser *user.User
	if normalizedEmail != "" {
		existingUser, err = s.ctx.Store().Users().GetByEmail(ctx, normalizedEmail)
		if err != nil && !errors.Is(err, corestore.ErrNotFound) {
			return nil, fmt.Errorf("oauth: check existing user by email: %w", err)
		}
	}

	if existingUser != nil {
		// Email match collision!
		// CRITICAL SECURITY ENFORCEMENT: Prevent unsafe automatic account linking.
		switch s.cfg.LinkingPolicy {
		case LinkingPolicyDisabled:
			s.publish(ctx, EventOAuthFailed, in.Provider, FailedPayload{Provider: in.Provider, Reason: "account_conflict"})
			return nil, ErrAccountConflict

		case LinkingPolicyExplicitOnly:
			s.publish(ctx, EventOAuthFailed, in.Provider, FailedPayload{Provider: in.Provider, Reason: "linking_consent_required"})
			return nil, ErrAccountLinkingRequiresConsent

		case LinkingPolicyVerifiedEmail:
			if !profile.EmailVerified || !existingUser.EmailVerified {
				s.publish(ctx, EventOAuthFailed, in.Provider, FailedPayload{Provider: in.Provider, Reason: "unverified_email_linking"})
				return nil, ErrUnverifiedEmailLinkingProhibited
			}

			// Both emails verified: link existing account and issue session inside transaction
			var (
				newAcc *account.Account
				issued *auth.IssuedSession
			)
			err = s.ctx.Store().Transaction(ctx, func(txCtx context.Context) error {
				newAcc = &account.Account{
					ID:         newID(),
					UserID:     existingUser.ID,
					Provider:   in.Provider,
					ProviderID: profile.ProviderID,
					CreatedAt:  now,
					UpdatedAt:  now,
				}
				if err := s.ctx.Store().Accounts().Create(txCtx, newAcc); err != nil {
					return err
				}

				issued, err = s.ctx.Core().CreateSession(txCtx, existingUser.ID, in.Session)
				return err
			})
			if err != nil {
				return nil, fmt.Errorf("oauth: link verified account: %w", err)
			}

			result := &AuthResult{
				User:          existingUser,
				Account:       newAcc,
				Session:       issued.Session,
				Token:         issued.Token,
				IsNewUser:     false,
				TokenResponse: tokenResp,
				Profile:       profile,
			}

			s.publish(ctx, EventOAuthAccountLinked, existingUser.ID, AccountLinkedPayload{
				UserID:     existingUser.ID,
				AccountID:  newAcc.ID,
				Provider:   in.Provider,
				ProviderID: profile.ProviderID,
			})
			s.publish(ctx, EventOAuthAuthenticated, existingUser.ID, AuthenticatedPayload{
				UserID:     existingUser.ID,
				AccountID:  newAcc.ID,
				Provider:   in.Provider,
				ProviderID: profile.ProviderID,
				IsNewUser:  false,
			})

			_ = s.hooks.runAfterOAuthSignIn(ctx, result)
			return result, nil

		default:
			return nil, ErrAccountLinkingRequiresConsent
		}
	}

	// 3. Brand new user registration
	if !s.cfg.AllowSignUp {
		s.publish(ctx, EventOAuthFailed, in.Provider, FailedPayload{Provider: in.Provider, Reason: "sign_up_disabled"})
		return nil, ErrSignUpDisabled
	}

	var (
		newUser *user.User
		newAcc  *account.Account
		issued  *auth.IssuedSession
	)

	err = s.ctx.Store().Transaction(ctx, func(txCtx context.Context) error {
		newUser = &user.User{
			ID:            newID(),
			Email:         normalizedEmail,
			EmailVerified: profile.EmailVerified,
			CreatedAt:     now,
			UpdatedAt:     now,
		}
		if err := s.ctx.Store().Users().Create(txCtx, newUser); err != nil {
			return err
		}

		newAcc = &account.Account{
			ID:         newID(),
			UserID:     newUser.ID,
			Provider:   in.Provider,
			ProviderID: profile.ProviderID,
			CreatedAt:  now,
			UpdatedAt:  now,
		}
		if err := s.ctx.Store().Accounts().Create(txCtx, newAcc); err != nil {
			return err
		}

		issued, err = s.ctx.Core().CreateSession(txCtx, newUser.ID, in.Session)
		return err
	})
	if err != nil {
		return nil, fmt.Errorf("oauth: create new user and account: %w", err)
	}

	result := &AuthResult{
		User:          newUser,
		Account:       newAcc,
		Session:       issued.Session,
		Token:         issued.Token,
		IsNewUser:     true,
		TokenResponse: tokenResp,
		Profile:       profile,
	}

	s.publish(ctx, EventOAuthUserCreated, newUser.ID, UserCreatedPayload{
		UserID:     newUser.ID,
		Email:      newUser.Email,
		Provider:   in.Provider,
		ProviderID: profile.ProviderID,
	})
	s.publish(ctx, EventOAuthAccountLinked, newUser.ID, AccountLinkedPayload{
		UserID:     newUser.ID,
		AccountID:  newAcc.ID,
		Provider:   in.Provider,
		ProviderID: profile.ProviderID,
	})
	s.publish(ctx, EventOAuthAuthenticated, newUser.ID, AuthenticatedPayload{
		UserID:     newUser.ID,
		AccountID:  newAcc.ID,
		Provider:   in.Provider,
		ProviderID: profile.ProviderID,
		IsNewUser:  true,
	})

	_ = s.hooks.runAfterOAuthSignIn(ctx, result)
	return result, nil
}

// CompleteLink completes an explicit account linking flow for an already authenticated user.
func (s *service) CompleteLink(ctx context.Context, in CompleteLinkInput) (*LinkResult, error) {
	if in.Code == "" || in.State == "" || in.RedirectURI == "" {
		return nil, fmt.Errorf("%w: code, state and redirect_uri are required", ErrInvalidInput)
	}

	now := s.now()
	stateSess, err := s.consumeState(ctx, in.State, now)
	if err != nil {
		return nil, err
	}

	if stateSess.Action != ActionLink || stateSess.UserID == "" {
		return nil, fmt.Errorf("%w: expected link action bound to user", ErrInvalidAction)
	}

	if stateSess.RedirectURI != in.RedirectURI {
		return nil, fmt.Errorf("%w: expected %q, got %q", ErrInvalidRedirectURI, stateSess.RedirectURI, in.RedirectURI)
	}

	p, ok := s.providers[stateSess.Provider]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrProviderNotFound, stateSess.Provider)
	}

	u, err := s.ctx.Core().RequireUser(ctx, stateSess.UserID)
	if err != nil {
		return nil, err
	}

	exchangeOpts := []provider.ExchangeOption{
		provider.WithExchangeRedirectURI(in.RedirectURI),
	}
	if stateSess.CodeVerifier != "" {
		exchangeOpts = append(exchangeOpts, provider.WithCodeVerifier(stateSess.CodeVerifier))
	}

	tokenResp, err := p.Exchange(ctx, in.Code, exchangeOpts...)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrTokenExchangeFailed, err)
	}

	profile, err := p.FetchProfile(ctx, tokenResp)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrProfileFetchFailed, err)
	}

	if profile.ProviderID == "" {
		return nil, ErrInvalidProfile
	}

	// Verify that this external identity is not already linked to another user
	existingAcc, err := s.ctx.Store().Accounts().GetByProvider(ctx, stateSess.Provider, profile.ProviderID)
	if err != nil && !errors.Is(err, corestore.ErrNotFound) {
		return nil, fmt.Errorf("oauth: check account uniqueness: %w", err)
	}
	if existingAcc != nil {
		return nil, ErrAccountAlreadyLinked
	}

	if err := s.hooks.runBeforeAccountLink(ctx, u.ID, profile); err != nil {
		return nil, err
	}

	newAcc := &account.Account{
		ID:         newID(),
		UserID:     u.ID,
		Provider:   stateSess.Provider,
		ProviderID: profile.ProviderID,
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	if err := s.ctx.Store().Accounts().Create(ctx, newAcc); err != nil {
		return nil, fmt.Errorf("oauth: create linked account: %w", err)
	}

	s.publish(ctx, EventOAuthAccountLinked, u.ID, AccountLinkedPayload{
		UserID:     u.ID,
		AccountID:  newAcc.ID,
		Provider:   stateSess.Provider,
		ProviderID: profile.ProviderID,
	})

	return &LinkResult{
		User:    u,
		Account: newAcc,
		Profile: profile,
	}, nil
}

// UnlinkAccount removes the link between a user and an OAuth provider.
func (s *service) UnlinkAccount(ctx context.Context, userID, providerName string) error {
	if userID == "" || providerName == "" {
		return fmt.Errorf("%w: user_id and provider are required", ErrInvalidInput)
	}

	accounts, err := s.ctx.Store().Accounts().ListByUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("oauth: list accounts: %w", err)
	}

	var target *account.Account
	for _, acc := range accounts {
		if acc.Provider == providerName {
			target = acc
			break
		}
	}
	if target == nil {
		return ErrAccountNotFound
	}

	// Safeguard: Prevent orphaning the user if this is their sole auth method
	if !s.cfg.AllowOrphanUser {
		creds, err := s.ctx.Store().Credentials().ListByUser(ctx, userID)
		if err != nil {
			return fmt.Errorf("oauth: list credentials: %w", err)
		}
		if len(accounts) <= 1 && len(creds) == 0 {
			return ErrCannotUnlinkSoleAuthMethod
		}
	}

	if err := s.ctx.Store().Accounts().Delete(ctx, target.ID); err != nil {
		return fmt.Errorf("oauth: delete account: %w", err)
	}

	s.publish(ctx, EventOAuthAccountUnlinked, userID, AccountUnlinkedPayload{
		UserID:    userID,
		AccountID: target.ID,
		Provider:  providerName,
	})

	return nil
}

// ListAccounts returns all external OAuth accounts linked to the user.
func (s *service) ListAccounts(ctx context.Context, userID string) ([]*account.Account, error) {
	if userID == "" {
		return nil, fmt.Errorf("%w: user_id is required", ErrInvalidInput)
	}
	return s.ctx.Store().Accounts().ListByUser(ctx, userID)
}

// GetProvider returns a registered provider by name.
func (s *service) GetProvider(name string) (provider.Provider, error) {
	p, ok := s.providers[name]
	if !ok {
		return nil, ErrProviderNotFound
	}
	return p, nil
}

// PurgeExpired cleans up expired states from the store.
func (s *service) PurgeExpired(ctx context.Context) (int, error) {
	affected, err := s.states.Delete(ctx, adapter.Lt("expires_at", s.now()))
	return int(affected), err
}

func generateRandomToken(byteLength int) (string, error) {
	b := make([]byte, byteLength)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func newID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
