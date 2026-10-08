package passkey

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"github.com/BladiCreator/go-modular-auth-passkeys/challenge"
	passkeystore "github.com/BladiCreator/go-modular-auth-passkeys/store"
	"github.com/BladiCreator/go-modular-auth/account"
	auth "github.com/BladiCreator/go-modular-auth"
	corestore "github.com/BladiCreator/go-modular-auth/store"
	"github.com/BladiCreator/go-modular-auth/user"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

type service struct {
	host       *auth.Host
	cfg        Config
	store      passkeystore.Store
	challenges challenge.Store
	webauthn   *webauthn.WebAuthn
	hooks      *Hooks
}

var _ Passkeys = (*service)(nil)

func newService(h *auth.Host, cfg Config) (*service, error) {
	requireResidentKey := cfg.ResidentKey == protocol.ResidentKeyRequirementRequired

	wcfg := &webauthn.Config{
		RPDisplayName: cfg.RPDisplayName,
		RPID:          cfg.RPID,
		RPOrigins:     cfg.RPOrigins,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			UserVerification:   cfg.UserVerification,
			RequireResidentKey: &requireResidentKey,
			ResidentKey:        cfg.ResidentKey,
		},
		EncodeUserIDAsString: true,
		Debug:                cfg.Debug,
		Timeouts: webauthn.TimeoutsConfig{
			Login: webauthn.TimeoutConfig{
				Enforce: true,
				Timeout: cfg.Timeout,
			},
			Registration: webauthn.TimeoutConfig{
				Enforce: true,
				Timeout: cfg.Timeout,
			},
		},
	}

	wa, err := webauthn.New(wcfg)
	if err != nil {
		return nil, fmt.Errorf("passkey: initialize webauthn engine: %w", err)
	}

	return &service{
		host:       h,
		cfg:        cfg,
		store:      cfg.Store,
		challenges: cfg.ChallengeStore,
		webauthn:   wa,
		hooks:      cfg.Hooks,
	}, nil
}

// webAuthnUserAdapter implements the webauthn.User interface for GoModularAuth users.
type webAuthnUserAdapter struct {
	u           *user.User
	credentials []*Passkey
}

var _ webauthn.User = (*webAuthnUserAdapter)(nil)

func newWebAuthnUser(u *user.User, creds []*Passkey) *webAuthnUserAdapter {
	return &webAuthnUserAdapter{
		u:           u,
		credentials: creds,
	}
}

func (w *webAuthnUserAdapter) WebAuthnID() []byte {
	return []byte(w.u.ID)
}

func (w *webAuthnUserAdapter) WebAuthnName() string {
	return w.u.Email
}

func (w *webAuthnUserAdapter) WebAuthnDisplayName() string {
	if w.u.Email != "" {
		return w.u.Email
	}
	return w.u.ID
}

func (w *webAuthnUserAdapter) WebAuthnIcon() string {
	return ""
}

func (w *webAuthnUserAdapter) WebAuthnCredentials() []webauthn.Credential {
	result := make([]webauthn.Credential, 0, len(w.credentials))
	for _, c := range w.credentials {
		if c.Active() {
			result = append(result, c.ToWebAuthn())
		}
	}
	return result
}

// BeginRegistration initiates the WebAuthn registration ceremony.
func (s *service) BeginRegistration(ctx context.Context, in BeginRegistrationInput) (*RegistrationOptions, error) {
	if in.UserID == "" {
		return nil, ErrUserIDRequired
	}

	if err := s.hooks.runBeforeBeginRegistration(ctx, &in); err != nil {
		return nil, err
	}

	u, err := s.host.Store().Users().GetByID(ctx, in.UserID)
	if err != nil {
		if errors.Is(err, corestore.ErrNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	existing, err := s.store.ListCredentialsByUser(ctx, u.ID)
	if err != nil {
		return nil, err
	}

	userAdapter := newWebAuthnUser(u, existing)

	excludeList := make([]protocol.CredentialDescriptor, 0, len(existing))
	for _, c := range existing {
		if c.Active() {
			excludeList = append(excludeList, c.ToWebAuthn().Descriptor())
		}
	}

	opts := []webauthn.RegistrationOption{
		webauthn.WithExclusions(excludeList),
	}

	if in.ResidentKey != "" {
		opts = append(opts, webauthn.WithResidentKeyRequirement(in.ResidentKey))
	}

	if in.UserVerification != "" || in.AuthenticatorAttachment != "" {
		requireResidentKey := s.cfg.ResidentKey == protocol.ResidentKeyRequirementRequired
		opts = append(opts, webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			AuthenticatorAttachment: in.AuthenticatorAttachment,
			RequireResidentKey:      &requireResidentKey,
			ResidentKey:             s.cfg.ResidentKey,
			UserVerification:        in.UserVerification,
		}))
	}

	creation, sessionData, err := s.webauthn.BeginRegistration(userAdapter, opts...)
	if err != nil {
		return nil, &CeremonyError{Op: "begin_registration", Reason: "webauthn options generation", Underlying: err}
	}

	sessionID, err := generateSecureToken()
	if err != nil {
		return nil, err
	}

	now := s.host.Now()
	expiresAt := sessionData.Expires
	if expiresAt.IsZero() {
		expiresAt = now.Add(s.cfg.Timeout)
	}

	cSession := &challenge.Session{
		ID:           sessionID,
		Type:         challenge.CeremonyRegistration,
		UserID:       u.ID,
		FriendlyName: in.FriendlyName,
		Data:         *sessionData,
		CreatedAt:    now,
		ExpiresAt:    expiresAt,
	}

	if err := s.challenges.Save(ctx, cSession); err != nil {
		return nil, err
	}

	return &RegistrationOptions{
		SessionID: sessionID,
		Options:   creation,
		ExpiresAt: expiresAt,
	}, nil
}

// FinishRegistration completes the WebAuthn registration ceremony.
func (s *service) FinishRegistration(ctx context.Context, in FinishRegistrationInput) (*Passkey, error) {
	if in.SessionID == "" {
		return nil, ErrSessionIDRequired
	}

	if err := s.hooks.runBeforeFinishRegistration(ctx, &in); err != nil {
		return nil, err
	}

	sess, err := s.challenges.Consume(ctx, in.SessionID)
	if err != nil {
		if errors.Is(err, challenge.ErrNotFound) {
			return nil, ErrChallengeNotFound
		}
		if errors.Is(err, challenge.ErrExpired) {
			return nil, ErrChallengeExpired
		}
		if errors.Is(err, challenge.ErrAlreadyConsumed) {
			return nil, ErrChallengeAlreadyUsed
		}
		return nil, err
	}

	if sess.Type != challenge.CeremonyRegistration {
		return nil, ErrChallengeTypeMismatch
	}

	parsed, err := parseRegistrationResponse(in)
	if err != nil {
		return nil, err
	}

	u, err := s.host.Store().Users().GetByID(ctx, sess.UserID)
	if err != nil {
		if errors.Is(err, corestore.ErrNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	existing, err := s.store.ListCredentialsByUser(ctx, u.ID)
	if err != nil {
		return nil, err
	}

	userAdapter := newWebAuthnUser(u, existing)

	cred, err := s.webauthn.CreateCredential(userAdapter, sess.Data, parsed)
	if err != nil {
		return nil, &CeremonyError{Op: "finish_registration", Reason: "verification failed", Underlying: err}
	}

	// Prevent duplicate credential registration
	if _, err := s.store.GetCredentialByID(ctx, cred.ID); err == nil {
		return nil, ErrCredentialAlreadyExists
	}

	friendlyName := in.FriendlyName
	if friendlyName == "" {
		friendlyName = sess.FriendlyName
	}

	now := s.host.Now()
	pass := FromWebAuthn(u.ID, friendlyName, cred, now)

	// Persist to passkey store
	if err := s.store.SaveCredential(ctx, pass); err != nil {
		if errors.Is(err, passkeystore.ErrConflict) {
			return nil, ErrCredentialAlreadyExists
		}
		return nil, err
	}

	// Link account in core store
	accountID, _ := generateSecureToken()
	acc := &account.Account{
		ID:         accountID,
		UserID:     u.ID,
		Provider:   ProviderPasskey,
		ProviderID: pass.ID,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	if err := s.host.Store().Accounts().Create(ctx, acc); err != nil && !errors.Is(err, corestore.ErrConflict) {
		s.host.Logger().ErrorContext(ctx, "passkey: failed to link core account", "user_id", u.ID, "error", err)
	}

	if err := s.hooks.runAfterRegistration(ctx, pass); err != nil {
		return nil, err
	}

	s.host.Events().Publish(ctx, auth.Event{
		Name:    EventPasskeyRegistered,
		Time:    now,
		Subject: u.ID,
		Payload: PasskeyRegisteredPayload{
			UserID:       u.ID,
			CredentialID: pass.ID,
			FriendlyName: pass.FriendlyName,
			AAGUID:       hex.EncodeToString(pass.AAGUID),
			RegisteredAt: now,
		},
	})

	return pass, nil
}

// BeginAuthentication initiates the WebAuthn authentication ceremony.
func (s *service) BeginAuthentication(ctx context.Context, in BeginAuthenticationInput) (*AuthenticationOptions, error) {
	if err := s.hooks.runBeforeBeginAuthentication(ctx, &in); err != nil {
		return nil, err
	}

	var opts []webauthn.LoginOption
	if in.UserVerification != "" {
		opts = append(opts, webauthn.WithUserVerification(in.UserVerification))
	}

	var (
		assertion   *protocol.CredentialAssertion
		sessionData *webauthn.SessionData
		err         error
	)

	if in.UserID != "" {
		// Non-discoverable ceremony targeted at a known user
		u, errUser := s.host.Store().Users().GetByID(ctx, in.UserID)
		if errUser != nil {
			if errors.Is(errUser, corestore.ErrNotFound) {
				return nil, ErrUserNotFound
			}
			return nil, errUser
		}

		creds, errCreds := s.store.ListCredentialsByUser(ctx, u.ID)
		if errCreds != nil {
			return nil, errCreds
		}
		if len(creds) == 0 {
			return nil, ErrCredentialNotFound
		}

		userAdapter := newWebAuthnUser(u, creds)
		assertion, sessionData, err = s.webauthn.BeginLogin(userAdapter, opts...)
	} else {
		// Discoverable (resident key / usernameless) ceremony
		assertion, sessionData, err = s.webauthn.BeginDiscoverableLogin(opts...)
	}

	if err != nil {
		return nil, &CeremonyError{Op: "begin_authentication", Reason: "webauthn assertion generation", Underlying: err}
	}

	sessionID, err := generateSecureToken()
	if err != nil {
		return nil, err
	}

	now := s.host.Now()
	expiresAt := sessionData.Expires
	if expiresAt.IsZero() {
		expiresAt = now.Add(s.cfg.Timeout)
	}

	cSession := &challenge.Session{
		ID:        sessionID,
		Type:      challenge.CeremonyAuthentication,
		UserID:    in.UserID,
		Data:      *sessionData,
		CreatedAt: now,
		ExpiresAt: expiresAt,
	}

	if err := s.challenges.Save(ctx, cSession); err != nil {
		return nil, err
	}

	return &AuthenticationOptions{
		SessionID: sessionID,
		Options:   assertion,
		ExpiresAt: expiresAt,
	}, nil
}

// FinishAuthentication completes the WebAuthn authentication ceremony.
func (s *service) FinishAuthentication(ctx context.Context, in FinishAuthenticationInput) (*auth.AuthResult, error) {
	if in.SessionID == "" {
		return nil, ErrSessionIDRequired
	}

	if err := s.hooks.runBeforeFinishAuthentication(ctx, &in); err != nil {
		return nil, err
	}

	sess, err := s.challenges.Consume(ctx, in.SessionID)
	if err != nil {
		if errors.Is(err, challenge.ErrNotFound) {
			return nil, ErrChallengeNotFound
		}
		if errors.Is(err, challenge.ErrExpired) {
			return nil, ErrChallengeExpired
		}
		if errors.Is(err, challenge.ErrAlreadyConsumed) {
			return nil, ErrChallengeAlreadyUsed
		}
		return nil, err
	}

	if sess.Type != challenge.CeremonyAuthentication {
		return nil, ErrChallengeTypeMismatch
	}

	parsed, err := parseAssertionResponse(in)
	if err != nil {
		return nil, err
	}

	var (
		authenticatedUser *user.User
		validatedCred     *webauthn.Credential
	)

	if sess.UserID != "" {
		u, err := s.host.Store().Users().GetByID(ctx, sess.UserID)
		if err != nil {
			if errors.Is(err, corestore.ErrNotFound) {
				return nil, ErrUserNotFound
			}
			return nil, err
		}

		creds, err := s.store.ListCredentialsByUser(ctx, u.ID)
		if err != nil {
			return nil, err
		}

		userAdapter := newWebAuthnUser(u, creds)
		vCred, err := s.webauthn.ValidateLogin(userAdapter, sess.Data, parsed)
		if err != nil {
			return nil, &CeremonyError{Op: "finish_authentication", Reason: "assertion verification", Underlying: err}
		}

		authenticatedUser = u
		validatedCred = vCred
	} else {
		// Discoverable passkey login: resolve user from assertion userHandle or raw credential ID
		discoverableHandler := func(rawID, userHandle []byte) (webauthn.User, error) {
			var targetUserID string
			if len(userHandle) > 0 {
				targetUserID = string(userHandle)
			} else {
				credRecord, err := s.store.GetCredentialByID(ctx, rawID)
				if err != nil {
					return nil, err
				}
				targetUserID = credRecord.UserID
			}

			u, err := s.host.Store().Users().GetByID(ctx, targetUserID)
			if err != nil {
				return nil, err
			}

			creds, err := s.store.ListCredentialsByUser(ctx, u.ID)
			if err != nil {
				return nil, err
			}

			return newWebAuthnUser(u, creds), nil
		}

		waUser, vCred, err := s.webauthn.ValidatePasskeyLogin(discoverableHandler, sess.Data, parsed)
		if err != nil {
			return nil, &CeremonyError{Op: "finish_authentication", Reason: "discoverable verification", Underlying: err}
		}

		adapter, ok := waUser.(*webAuthnUserAdapter)
		if !ok {
			return nil, errors.New("passkey: unexpected user adapter type")
		}

		authenticatedUser = adapter.u
		validatedCred = vCred
	}

	// Sign counter verification and clone detection
	storedPasskey, err := s.store.GetCredentialByID(ctx, validatedCred.ID)
	if err != nil {
		if errors.Is(err, passkeystore.ErrNotFound) {
			return nil, ErrCredentialNotFound
		}
		return nil, err
	}

	if validatedCred.Authenticator.CloneWarning {
		return nil, ErrAuthenticatorCloned
	}

	if s.cfg.EnforceSignCounter {
		// If stored counter is non-zero, the new counter must be strictly greater than stored counter
		if storedPasskey.SignCount > 0 && validatedCred.Authenticator.SignCount != 0 {
			if validatedCred.Authenticator.SignCount <= storedPasskey.SignCount {
				return nil, ErrSignCounterInvalid
			}
		}
	}

	now := s.host.Now()

	// Update stored passkey counters and timestamps
	storedPasskey.SignCount = validatedCred.Authenticator.SignCount
	storedPasskey.CloneWarning = validatedCred.Authenticator.CloneWarning
	storedPasskey.BackupState = validatedCred.Flags.BackupState
	storedPasskey.LastUsedAt = &now
	storedPasskey.UpdatedAt = now

	if err := s.store.UpdateCredential(ctx, storedPasskey); err != nil {
		s.host.Logger().ErrorContext(ctx, "passkey: failed to update credential sign counter", "error", err)
	}

	// Establish authenticated session via Core
	issued, err := s.host.Auth().CreateSession(ctx, authenticatedUser.ID, in.Session)
	if err != nil {
		return nil, fmt.Errorf("passkey: issue core session: %w", err)
	}

	s.host.Events().Publish(ctx, auth.Event{
		Name:    EventPasskeyUsed,
		Time:    now,
		Subject: authenticatedUser.ID,
		Payload: PasskeyUsedPayload{
			UserID:       authenticatedUser.ID,
			CredentialID: storedPasskey.ID,
			SessionID:    issued.Session.ID,
			UsedAt:       now,
		},
	})

	res := &auth.AuthResult{
		User:    authenticatedUser,
		Session: issued.Session,
		Token:   issued.Token,
	}

	if err := s.hooks.runAfterAuthentication(ctx, res); err != nil {
		return nil, err
	}

	return res, nil
}

// ListCredentials returns all active passkeys registered to a user.
func (s *service) ListCredentials(ctx context.Context, userID string) ([]*Passkey, error) {
	if userID == "" {
		return nil, ErrUserIDRequired
	}
	return s.store.ListCredentialsByUser(ctx, userID)
}

// GetCredential returns a single passkey by credential ID with ownership verification.
func (s *service) GetCredential(ctx context.Context, userID string, credentialID []byte) (*Passkey, error) {
	if userID == "" {
		return nil, ErrUserIDRequired
	}
	if len(credentialID) == 0 {
		return nil, ErrCredentialIDRequired
	}

	cred, err := s.store.GetCredentialByID(ctx, credentialID)
	if err != nil {
		if errors.Is(err, passkeystore.ErrNotFound) {
			return nil, ErrCredentialNotFound
		}
		return nil, err
	}

	if cred.UserID != userID {
		return nil, ErrCredentialNotFound
	}

	return cred, nil
}

// UpdateCredential updates passkey metadata such as friendly name.
func (s *service) UpdateCredential(ctx context.Context, in UpdateCredentialInput) (*Passkey, error) {
	if in.UserID == "" {
		return nil, ErrUserIDRequired
	}
	if len(in.CredentialID) == 0 {
		return nil, ErrCredentialIDRequired
	}

	cred, err := s.store.GetCredentialByID(ctx, in.CredentialID)
	if err != nil {
		if errors.Is(err, passkeystore.ErrNotFound) {
			return nil, ErrCredentialNotFound
		}
		return nil, err
	}

	if cred.UserID != in.UserID {
		return nil, ErrCredentialNotFound
	}

	cred.FriendlyName = in.FriendlyName
	cred.UpdatedAt = s.host.Now()

	if err := s.store.UpdateCredential(ctx, cred); err != nil {
		return nil, err
	}

	return cred, nil
}

// DeleteCredential revokes a passkey and removes its corresponding core account link.
func (s *service) DeleteCredential(ctx context.Context, in DeleteCredentialInput) error {
	if in.UserID == "" {
		return ErrUserIDRequired
	}
	if len(in.CredentialID) == 0 {
		return ErrCredentialIDRequired
	}

	cred, err := s.store.GetCredentialByID(ctx, in.CredentialID)
	if err != nil {
		if errors.Is(err, passkeystore.ErrNotFound) {
			return ErrCredentialNotFound
		}
		return err
	}

	if cred.UserID != in.UserID {
		return ErrCredentialNotFound
	}

	if err := s.store.DeleteCredential(ctx, in.CredentialID); err != nil {
		return err
	}

	// Clean up Core account if present
	accounts, err := s.host.Store().Accounts().ListByUser(ctx, in.UserID)
	if err == nil {
		for _, acc := range accounts {
			if acc.Provider == ProviderPasskey && acc.ProviderID == cred.ID {
				_ = s.host.Store().Accounts().Delete(ctx, acc.ID)
			}
		}
	}

	now := s.host.Now()
	s.host.Events().Publish(ctx, auth.Event{
		Name:    EventPasskeyRevoked,
		Time:    now,
		Subject: in.UserID,
		Payload: PasskeyRevokedPayload{
			UserID:       in.UserID,
			CredentialID: cred.ID,
			RevokedAt:    now,
		},
	})

	return nil
}

func parseRegistrationResponse(in FinishRegistrationInput) (*protocol.ParsedCredentialCreationData, error) {
	if in.ParsedResponse != nil {
		return in.ParsedResponse, nil
	}
	if len(in.Response) > 0 {
		parsed, err := protocol.ParseCredentialCreationResponseBytes(in.Response)
		if err != nil {
			return nil, &CeremonyError{Op: "parse_registration", Reason: "parse json bytes", Underlying: err}
		}
		return parsed, nil
	}
	if in.Body != nil {
		parsed, err := protocol.ParseCredentialCreationResponseBody(in.Body)
		if err != nil {
			return nil, &CeremonyError{Op: "parse_registration", Reason: "parse response body", Underlying: err}
		}
		return parsed, nil
	}
	return nil, ErrInvalidClientResponse
}

func parseAssertionResponse(in FinishAuthenticationInput) (*protocol.ParsedCredentialAssertionData, error) {
	if in.ParsedResponse != nil {
		return in.ParsedResponse, nil
	}
	if len(in.Response) > 0 {
		parsed, err := protocol.ParseCredentialRequestResponseBytes(in.Response)
		if err != nil {
			return nil, &CeremonyError{Op: "parse_authentication", Reason: "parse json bytes", Underlying: err}
		}
		return parsed, nil
	}
	if in.Body != nil {
		parsed, err := protocol.ParseCredentialRequestResponseBody(in.Body)
		if err != nil {
			return nil, &CeremonyError{Op: "parse_authentication", Reason: "parse response body", Underlying: err}
		}
		return parsed, nil
	}
	return nil, ErrInvalidClientResponse
}

func generateSecureToken() (string, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", fmt.Errorf("passkey: read crypto/rand: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
