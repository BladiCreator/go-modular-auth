package oidc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth/account"
	"github.com/BladiCreator/go-modular-auth/adapter"
	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
	corestore "github.com/BladiCreator/go-modular-auth/store"
	"github.com/BladiCreator/go-modular-auth/user"
)

type service struct {
	ctx       *sdk.Context
	cfg       Config
	logger    *slog.Logger
	jwksCache *jwksCache
	states    *sdk.Repository[StateSession]
	mu        sync.RWMutex
	providers map[string]ProviderConfig
}

var _ OIDC = (*service)(nil)

func newService(ctx *sdk.Context, cfg Config) *service {
	var logger *slog.Logger
	var states *sdk.Repository[StateSession]
	if ctx != nil {
		logger = ctx.Logger()
		states = sdk.Model[StateSession](ctx, ModelOIDCStates)
	} else {
		logger = slog.Default()
	}

	s := &service{
		ctx:       ctx,
		cfg:       cfg,
		logger:    logger,
		jwksCache: newJWKSCache(),
		states:    states,
		providers: make(map[string]ProviderConfig),
	}

	for k, v := range cfg.Providers {
		s.providers[k] = v
	}

	return s
}

// BeginAuth initiates an OIDC authorization code flow with PKCE and Nonce.
func (s *service) BeginAuth(ctx context.Context, in BeginAuthInput) (*BeginAuthResult, error) {
	return s.beginFlow(ctx, in.Provider, in.RedirectURI, in.Scopes, in.Prompt, in.Metadata, ActionSignIn, "")
}

// BeginLink initiates an OIDC flow specifically for linking a provider to an existing authenticated user.
func (s *service) BeginLink(ctx context.Context, in BeginLinkInput) (*BeginAuthResult, error) {
	if in.UserID == "" {
		return nil, fmt.Errorf("%w: user_id is required for account linking", ErrInvalidInput)
	}
	return s.beginFlow(ctx, in.Provider, in.RedirectURI, in.Scopes, in.Prompt, in.Metadata, ActionLink, in.UserID)
}

func (s *service) beginFlow(ctx context.Context, providerID, redirectURI string, scopes []string, prompt string, metadata map[string]string, action Action, userID string) (*BeginAuthResult, error) {
	if providerID == "" || redirectURI == "" {
		return nil, fmt.Errorf("%w: provider and redirect_uri are required", ErrInvalidInput)
	}

	p, err := s.GetProvider(providerID)
	if err != nil {
		return nil, err
	}

	endpoints, err := s.resolveEndpoints(ctx, p)
	if err != nil {
		return nil, err
	}

	state, err := generateRandomString(32)
	if err != nil {
		return nil, fmt.Errorf("oidc: generate state: %w", err)
	}

	nonce, err := generateRandomString(32)
	if err != nil {
		return nil, fmt.Errorf("oidc: generate nonce: %w", err)
	}

	pkce, err := GeneratePKCE()
	if err != nil {
		return nil, fmt.Errorf("oidc: generate pkce: %w", err)
	}

	now := s.cfg.Clock()
	expiresAt := now.Add(s.cfg.StateTTL)

	stateSess := &StateSession{
		State:        state,
		Provider:     providerID,
		RedirectURI:  redirectURI,
		CodeVerifier: pkce.Verifier,
		Nonce:        nonce,
		Action:       action,
		UserID:       userID,
		Metadata:     metadata,
		ExpiresAt:    expiresAt,
		CreatedAt:    now,
	}

	if err := s.states.Create(ctx, stateSess); err != nil {
		return nil, fmt.Errorf("oidc: save state session: %w", err)
	}

	// Build authorization URL
	allScopes := p.Scopes
	if len(scopes) > 0 {
		allScopes = scopes
	}
	if !contains(allScopes, "openid") {
		allScopes = append([]string{"openid"}, allScopes...)
	}

	authValues := url.Values{}
	authValues.Set("client_id", p.ClientID)
	authValues.Set("response_type", "code")
	authValues.Set("redirect_uri", redirectURI)
	authValues.Set("scope", strings.Join(allScopes, " "))
	authValues.Set("state", state)
	authValues.Set("nonce", nonce)
	authValues.Set("code_challenge", pkce.Challenge)
	authValues.Set("code_challenge_method", pkce.Method)
	if prompt != "" {
		authValues.Set("prompt", prompt)
	}

	delim := "?"
	if strings.Contains(endpoints.AuthURL, "?") {
		delim = "&"
	}
	authURL := endpoints.AuthURL + delim + authValues.Encode()

	return &BeginAuthResult{
		AuthURL:      authURL,
		State:        state,
		Nonce:        nonce,
		CodeVerifier: pkce.Verifier,
		ExpiresAt:    expiresAt,
	}, nil
}

// CompleteAuth completes an OIDC authorization code flow for authentication.
func (s *service) CompleteAuth(ctx context.Context, in CompleteAuthInput) (*AuthResult, error) {
	if in.Provider == "" || in.Code == "" || in.State == "" || in.RedirectURI == "" {
		return nil, fmt.Errorf("%w: provider, code, state and redirect_uri are required", ErrInvalidInput)
	}

	p, err := s.GetProvider(in.Provider)
	if err != nil {
		return nil, err
	}

	now := s.cfg.Clock()
	stateSess, err := s.consumeState(ctx, in.State, now)
	if err != nil {
		return nil, err
	}

	if stateSess.Expired(now) {
		return nil, ErrStateExpired
	}
	if stateSess.Provider != in.Provider || stateSess.RedirectURI != in.RedirectURI {
		return nil, ErrInvalidState
	}
	if stateSess.Action != ActionSignIn {
		return nil, fmt.Errorf("%w: state token was issued for account linking", ErrInvalidState)
	}

	endpoints, err := s.resolveEndpoints(ctx, p)
	if err != nil {
		return nil, err
	}

	// 1. Exchange authorization code for tokens
	tokenResp, err := s.exchangeCode(ctx, p, endpoints.TokenURL, in.Code, in.RedirectURI, stateSess.CodeVerifier)
	if err != nil {
		s.publish(ctx, EventOIDCFailed, in.Provider, FailedPayload{
			Provider:   in.Provider,
			Reason:     err.Error(),
			OccurredAt: now,
		})
		return nil, err
	}

	if tokenResp.IDToken == "" {
		return nil, ErrMissingIDToken
	}

	// 2. Fetch JWKS and cryptographically verify ID token
	jwks, err := s.fetchJWKS(ctx, endpoints.JWKSURL)
	if err != nil {
		return nil, fmt.Errorf("oidc: fetch jwks: %w", err)
	}

	claims, err := ParseAndVerifyIDToken(tokenResp.IDToken, *p, jwks, stateSess.Nonce, now)
	if err != nil {
		s.publish(ctx, EventOIDCFailed, in.Provider, FailedPayload{
			Provider:   in.Provider,
			Reason:     "invalid_id_token",
			OccurredAt: now,
		})
		return nil, err
	}

	// 3. Core Account Resolution & Linking
	acc, err := s.ctx.Store().Accounts().GetByProvider(ctx, in.Provider, claims.Subject)
	if err != nil && !errors.Is(err, corestore.ErrNotFound) {
		return nil, fmt.Errorf("oidc: lookup account: %w", err)
	}

	if acc != nil {
		// Existing account found: Authenticate user directly
		u, err := s.ctx.Core().GetUser(ctx, acc.UserID)
		if err != nil {
			return nil, fmt.Errorf("oidc: get user: %w", err)
		}
		if u == nil {
			return nil, auth.ErrUserNotFound
		}

		issued, err := s.ctx.Core().CreateSession(ctx, u.ID, in.Session)
		if err != nil {
			return nil, fmt.Errorf("oidc: create session: %w", err)
		}

		result := &AuthResult{
			User:          u,
			Account:       acc,
			Session:       issued.Session,
			Token:         issued.Token,
			IsNewUser:     false,
			IDTokenClaims: claims,
			TokenResponse: tokenResp,
		}

		s.publish(ctx, EventOIDCAuthenticated, u.ID, AuthenticatedPayload{
			UserID:     u.ID,
			AccountID:  acc.ID,
			Provider:   in.Provider,
			Subject:    claims.Subject,
			IsNewUser:  false,
			OccurredAt: now,
		})

		return result, nil
	}

	// 4. Account not found: Check if email exists in Core Users
	var existingUser *user.User
	if claims.Email != "" {
		normEmail, _ := user.NormalizeEmail(claims.Email)
		if normEmail != "" {
			existingUser, err = s.ctx.Store().Users().GetByEmail(ctx, normEmail)
			if err != nil && !errors.Is(err, corestore.ErrNotFound) {
				return nil, fmt.Errorf("oidc: lookup user by email: %w", err)
			}
		}
	}

	if existingUser != nil {
		// Email collision! Enforce Linking Policy
		switch s.cfg.LinkingPolicy {
		case LinkingPolicyDisabled:
			return nil, ErrAccountConflict
		case LinkingPolicyExplicitOnly:
			return nil, ErrAccountLinkingRequiresConsent
		case LinkingPolicyVerifiedEmail:
			if !claims.EmailVerified || !existingUser.EmailVerified {
				return nil, ErrUnverifiedEmailLinkingProhibited
			}

			var (
				newAcc *account.Account
				issued *auth.IssuedSession
			)
			err = s.ctx.Store().Transaction(ctx, func(txCtx context.Context) error {
				newAcc = &account.Account{
					ID:         newRecordID("acc"),
					UserID:     existingUser.ID,
					Provider:   in.Provider,
					ProviderID: claims.Subject,
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
				return nil, fmt.Errorf("oidc: link verified account: %w", err)
			}

			res := &AuthResult{
				User:          existingUser,
				Account:       newAcc,
				Session:       issued.Session,
				Token:         issued.Token,
				IsNewUser:     false,
				IDTokenClaims: claims,
				TokenResponse: tokenResp,
			}

			s.publish(ctx, EventOIDCAuthenticated, existingUser.ID, AuthenticatedPayload{
				UserID:     existingUser.ID,
				AccountID:  newAcc.ID,
				Provider:   in.Provider,
				Subject:    claims.Subject,
				IsNewUser:  false,
				OccurredAt: now,
			})
			return res, nil
		}
	}

	// 5. User does not exist: Provision new user and account inside transaction
	var (
		newUser *user.User
		newAcc  *account.Account
		issued  *auth.IssuedSession
	)

	err = s.ctx.Store().Transaction(ctx, func(txCtx context.Context) error {
		newUser = &user.User{
			ID:            newRecordID("usr"),
			Email:         claims.Email,
			EmailVerified: claims.EmailVerified,
			CreatedAt:     now,
			UpdatedAt:     now,
		}
		if err := s.ctx.Store().Users().Create(txCtx, newUser); err != nil {
			return err
		}

		newAcc = &account.Account{
			ID:         newRecordID("acc"),
			UserID:     newUser.ID,
			Provider:   in.Provider,
			ProviderID: claims.Subject,
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
		return nil, fmt.Errorf("oidc: provision user: %w", err)
	}

	result := &AuthResult{
		User:          newUser,
		Account:       newAcc,
		Session:       issued.Session,
		Token:         issued.Token,
		IsNewUser:     true,
		IDTokenClaims: claims,
		TokenResponse: tokenResp,
	}

	s.publish(ctx, EventOIDCAuthenticated, newUser.ID, AuthenticatedPayload{
		UserID:     newUser.ID,
		AccountID:  newAcc.ID,
		Provider:   in.Provider,
		Subject:    claims.Subject,
		IsNewUser:  true,
		OccurredAt: now,
	})

	return result, nil
}

// CompleteLink completes an account linking flow for the user bound during BeginLink.
func (s *service) CompleteLink(ctx context.Context, in CompleteLinkInput) (*LinkResult, error) {
	if in.Provider == "" || in.Code == "" || in.State == "" || in.RedirectURI == "" {
		return nil, fmt.Errorf("%w: provider, code, state and redirect_uri are required", ErrInvalidInput)
	}

	p, err := s.GetProvider(in.Provider)
	if err != nil {
		return nil, err
	}

	now := s.cfg.Clock()
	stateSess, err := s.consumeState(ctx, in.State, now)
	if err != nil {
		return nil, err
	}
	if stateSess.Action != ActionLink || stateSess.UserID == "" {
		return nil, fmt.Errorf("%w: state token was not issued for account linking", ErrInvalidState)
	}

	endpoints, err := s.resolveEndpoints(ctx, p)
	if err != nil {
		return nil, err
	}

	tokenResp, err := s.exchangeCode(ctx, p, endpoints.TokenURL, in.Code, in.RedirectURI, stateSess.CodeVerifier)
	if err != nil {
		return nil, err
	}

	jwks, err := s.fetchJWKS(ctx, endpoints.JWKSURL)
	if err != nil {
		return nil, err
	}

	claims, err := ParseAndVerifyIDToken(tokenResp.IDToken, *p, jwks, stateSess.Nonce, now)
	if err != nil {
		return nil, err
	}

	// Verify identity is not already linked to another user
	existingAcc, err := s.ctx.Store().Accounts().GetByProvider(ctx, in.Provider, claims.Subject)
	if err != nil && !errors.Is(err, corestore.ErrNotFound) {
		return nil, err
	}
	if existingAcc != nil {
		if existingAcc.UserID == stateSess.UserID {
			return &LinkResult{Account: existingAcc, IDTokenClaims: claims}, nil
		}
		return nil, ErrAccountConflict
	}

	newAcc := &account.Account{
		ID:         newRecordID("acc"),
		UserID:     stateSess.UserID,
		Provider:   in.Provider,
		ProviderID: claims.Subject,
		CreatedAt:  now,
		UpdatedAt:  now,
	}

	if err := s.ctx.Store().Accounts().Create(ctx, newAcc); err != nil {
		return nil, fmt.Errorf("oidc: create linked account: %w", err)
	}

	s.publish(ctx, EventOIDCAccountLinked, stateSess.UserID, LinkedPayload{
		UserID:     stateSess.UserID,
		AccountID:  newAcc.ID,
		Provider:   in.Provider,
		Subject:    claims.Subject,
		OccurredAt: now,
	})

	return &LinkResult{
		Account:       newAcc,
		IDTokenClaims: claims,
	}, nil
}

// UnlinkAccount removes the link between a user and an OIDC provider.
func (s *service) UnlinkAccount(ctx context.Context, userID, providerID string) error {
	accounts, err := s.ctx.Store().Accounts().ListByUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("oidc: list accounts: %w", err)
	}

	var target *account.Account
	for _, a := range accounts {
		if a.Provider == providerID {
			target = a
			break
		}
	}
	if target == nil {
		return errors.New("oidc: account link not found")
	}

	// Guard against unlinking sole login method
	if len(accounts) <= 1 {
		hasCredentials, err := s.ctx.Store().Credentials().ListByUser(ctx, userID)
		if err == nil && len(hasCredentials) == 0 {
			return ErrCannotUnlinkSoleAuthMethod
		}
	}

	if err := s.ctx.Store().Accounts().Delete(ctx, target.ID); err != nil {
		return fmt.Errorf("oidc: delete account: %w", err)
	}

	s.publish(ctx, EventOIDCAccountUnlinked, userID, UnlinkedPayload{
		UserID:     userID,
		AccountID:  target.ID,
		Provider:   providerID,
		OccurredAt: s.cfg.Clock(),
	})

	return nil
}

// ListAccounts returns all external OIDC accounts linked to the user.
func (s *service) ListAccounts(ctx context.Context, userID string) ([]*account.Account, error) {
	all, err := s.ctx.Store().Accounts().ListByUser(ctx, userID)
	if err != nil {
		return nil, err
	}

	var oidcAccounts []*account.Account
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, a := range all {
		if _, ok := s.providers[a.Provider]; ok {
			oidcAccounts = append(oidcAccounts, a)
		}
	}
	return oidcAccounts, nil
}

// ValidateIDToken cryptographically verifies a raw ID token against the provider's JWKS and issuer rules.
func (s *service) ValidateIDToken(ctx context.Context, providerID, rawIDToken, expectedNonce string) (*IDTokenClaims, error) {
	p, err := s.GetProvider(providerID)
	if err != nil {
		return nil, err
	}

	endpoints, err := s.resolveEndpoints(ctx, p)
	if err != nil {
		return nil, err
	}

	jwks, err := s.fetchJWKS(ctx, endpoints.JWKSURL)
	if err != nil {
		return nil, err
	}

	return ParseAndVerifyIDToken(rawIDToken, *p, jwks, expectedNonce, s.cfg.Clock())
}

// GetProvider returns a registered provider configuration.
func (s *service) GetProvider(providerID string) (*ProviderConfig, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	p, ok := s.providers[providerID]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrProviderNotFound, providerID)
	}
	return &p, nil
}

// Discover queries an OpenID Provider's discovery document (.well-known/openid-configuration).
func (s *service) Discover(ctx context.Context, issuerURL string) (*DiscoveryDocument, error) {
	discURL := strings.TrimRight(issuerURL, "/") + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := s.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDiscoveryFailed, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: status %d", ErrDiscoveryFailed, resp.StatusCode)
	}

	var doc DiscoveryDocument
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("%w: json decode: %v", ErrDiscoveryFailed, err)
	}

	return &doc, nil
}

func (s *service) resolveEndpoints(ctx context.Context, p *ProviderConfig) (*Endpoints, error) {
	if p.CustomEndpoints != nil && p.CustomEndpoints.AuthURL != "" && p.CustomEndpoints.TokenURL != "" && p.CustomEndpoints.JWKSURL != "" {
		return p.CustomEndpoints, nil
	}

	issuer := p.Issuer
	if p.DiscoveryURL != "" {
		issuer = p.DiscoveryURL
	}
	if issuer == "" {
		return nil, errors.New("oidc: provider has neither CustomEndpoints nor Issuer configured")
	}

	doc, err := s.Discover(ctx, issuer)
	if err != nil {
		return nil, err
	}

	return &Endpoints{
		AuthURL:     doc.AuthorizationEndpoint,
		TokenURL:    doc.TokenEndpoint,
		JWKSURL:     doc.JWKSUri,
		UserInfoURL: doc.UserInfoEndpoint,
	}, nil
}

func (s *service) fetchJWKS(ctx context.Context, jwksURI string) (JWKS, error) {
	if ks, ok := s.jwksCache.get(jwksURI, 1*time.Hour); ok {
		return ks, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURI, nil)
	if err != nil {
		return JWKS{}, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := s.cfg.HTTPClient.Do(req)
	if err != nil {
		return JWKS{}, fmt.Errorf("fetch jwks: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return JWKS{}, fmt.Errorf("fetch jwks: status %d", resp.StatusCode)
	}

	var ks JWKS
	if err := json.NewDecoder(resp.Body).Decode(&ks); err != nil {
		return JWKS{}, fmt.Errorf("decode jwks: %w", err)
	}

	s.jwksCache.set(jwksURI, ks)
	return ks, nil
}

func (s *service) exchangeCode(ctx context.Context, p *ProviderConfig, tokenURL, code, redirectURI, codeVerifier string) (*TokenResponse, error) {
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", redirectURI)
	form.Set("client_id", p.ClientID)
	if p.ClientSecret != "" {
		form.Set("client_secret", p.ClientSecret)
	}
	if codeVerifier != "" {
		form.Set("code_verifier", codeVerifier)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := s.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token exchange failed: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange error (status %d): %s", resp.StatusCode, string(bodyBytes))
	}

	var tok TokenResponse
	if err := json.Unmarshal(bodyBytes, &tok); err != nil {
		return nil, fmt.Errorf("unmarshal token response: %w", err)
	}

	return &tok, nil
}

func (s *service) publish(ctx context.Context, name auth.EventName, subject string, payload any) {
	if s.ctx != nil && s.ctx.Events() != nil {
		s.ctx.Events().Publish(ctx, auth.Event{
			Name:    name,
			Time:    s.cfg.Clock(),
			Subject: subject,
			Payload: payload,
		})
	}
}

func contains(slice []string, val string) bool {
	for _, item := range slice {
		if item == val {
			return true
		}
	}
	return false
}

func newRecordID(prefix string) string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return prefix + "_" + hex.EncodeToString(b)
}

func (s *service) consumeState(ctx context.Context, state string, now time.Time) (*StateSession, error) {
	if s.states == nil {
		return nil, ErrInvalidState
	}
	sess, err := s.states.FindOne(ctx, adapter.Eq("state", state))
	if errors.Is(err, adapter.ErrNotFound) || sess == nil {
		return nil, ErrInvalidState
	}
	if sess.IsConsumed() {
		return nil, ErrStateConsumed
	}
	if sess.Expired(now) {
		return nil, ErrStateExpired
	}

	n, err := s.states.Update(ctx, []adapter.Condition{
		adapter.Eq("state", state),
		adapter.IsNull("consumed_at"),
	}, map[string]any{
		"consumed_at": now,
	})
	if err != nil || n == 0 {
		return nil, ErrStateConsumed
	}
	sess.ConsumedAt = &now
	return sess, nil
}
