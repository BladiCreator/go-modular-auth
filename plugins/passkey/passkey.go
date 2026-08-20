package passkey

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/BladiCreator/go-modular-auth/plugin"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// Plugin implements the plugin.Plugin interface for FIDO2/WebAuthn Passkey authentication.
type Plugin struct {
	repo     Repository
	config   Config
	ctx      *plugin.Context
	webauthn *webauthn.WebAuthn
	mu       sync.RWMutex
}

// New creates and returns a new Passkey plugin configured with the given repository and options.
func New(repo Repository, opts ...Option) *Plugin {
	cfg := DefaultConfig()
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}

	return &Plugin{
		repo:   repo,
		config: cfg,
	}
}

// ID returns the unique identifier for the Passkey plugin.
func (p *Plugin) ID() string {
	return "passkey"
}

// Init initializes the plugin within the core engine and configures the WebAuthn cryptographic engine.
func (p *Plugin) Init(ctx *plugin.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.ctx = ctx

	// Store configuration in shared context
	ctx.Set(StoreKeyRPID, p.config.RPID)
	ctx.Set(StoreKeyRPOrigins, p.config.RPOrigins)
	ctx.Set(StoreKeyRPName, p.config.RPDisplayName)

	// Configure go-webauthn instance
	wConfig := &webauthn.Config{
		RPDisplayName:         p.config.RPDisplayName,
		RPID:                  p.config.RPID,
		RPOrigins:             p.config.RPOrigins,
		AttestationPreference: p.config.Attestation,
		AuthenticatorSelection: protocol.AuthenticatorSelection{
			ResidentKey:      p.config.ResidentKey,
			UserVerification: p.config.UserVerification,
		},
		Timeouts: webauthn.TimeoutsConfig{
			Login: webauthn.TimeoutConfig{
				Enforce: true,
				Timeout: p.config.ChallengeTimeout,
			},
			Registration: webauthn.TimeoutConfig{
				Enforce: true,
				Timeout: p.config.ChallengeTimeout,
			},
		},
	}

	if p.config.AuthenticatorAttachment != nil {
		wConfig.AuthenticatorSelection.AuthenticatorAttachment = *p.config.AuthenticatorAttachment
	}

	wInstance, err := webauthn.New(wConfig)
	if err != nil {
		return fmt.Errorf("passkey: failed to initialize webauthn engine: %w", err)
	}

	p.webauthn = wInstance
	return nil
}

// Config returns a copy of the current configuration.
func (p *Plugin) Config() Config {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.config
}

// GenerateRegistrationOptions begins a WebAuthn credential registration ceremony.
func (p *Plugin) GenerateRegistrationOptions(ctx context.Context, params *GenerateRegistrationOptionsParams) (*RegistrationOptionsResult, error) {
	p.mu.RLock()
	w := p.webauthn
	p.mu.RUnlock()

	if w == nil {
		return nil, fmt.Errorf("passkey: plugin not initialized")
	}

	if params == nil {
		params = &GenerateRegistrationOptionsParams{}
	}

	var userID, userName, userDisplayName string
	if params.UserID != "" {
		userID = params.UserID
		userName = params.UserName
		userDisplayName = params.UserDisplayName

		// If name not provided, attempt looking up user in repo
		if userName == "" || userDisplayName == "" {
			if u, err := p.repo.GetUserByID(ctx, userID); err == nil && u != nil {
				if userName == "" {
					userName = u.Email
				}
				if userDisplayName == "" {
					userDisplayName = u.Name
				}
			}
		}
	} else if !p.config.RequireSessionOnRegistration && p.config.ResolveUser != nil {
		resolved, err := p.config.ResolveUser(ctx, params.Context, params.Extra)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrInvalidResolvedUser, err)
		}
		if resolved == nil || resolved.ID == "" {
			return nil, ErrInvalidResolvedUser
		}
		userID = resolved.ID
		userName = resolved.Name
		userDisplayName = resolved.DisplayName
	} else if p.config.RequireSessionOnRegistration {
		return nil, ErrSessionRequired
	} else {
		return nil, ErrResolveUserRequired
	}

	if userName == "" {
		userName = userID
	}
	if userDisplayName == "" {
		userDisplayName = userName
	}

	// Fetch existing user credentials to prevent re-registering existing authenticators
	existingPasskeys, _ := p.repo.ListPasskeysByUserID(ctx, userID)
	webUser := buildWebAuthnUser(userID, userName, userDisplayName, existingPasskeys)

	var regOpts []webauthn.RegistrationOption
	if params.AuthenticatorAttachment != nil {
		regOpts = append(regOpts, webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			AuthenticatorAttachment: *params.AuthenticatorAttachment,
			ResidentKey:             p.config.ResidentKey,
			UserVerification:        p.config.UserVerification,
		}))
	}

	creation, sessionData, err := w.BeginRegistration(webUser, regOpts...)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrVerificationFailed, err)
	}

	sessionBytes, err := json.Marshal(sessionData)
	if err != nil {
		return nil, fmt.Errorf("passkey: failed to serialize session data: %w", err)
	}

	token, err := generateRandomHex(32)
	if err != nil {
		return nil, fmt.Errorf("passkey: failed to generate challenge token: %w", err)
	}

	expiresAt := time.Now().Add(p.config.ChallengeTimeout)
	challenge := &PasskeyChallenge{
		Token:       token,
		Type:        CeremonyRegistration,
		Challenge:   sessionData.Challenge,
		UserID:      &userID,
		UserName:    &userName,
		DisplayName: &userDisplayName,
		Context:     params.Context,
		SessionData: string(sessionBytes),
		ExpiresAt:   expiresAt,
		CreatedAt:   time.Now(),
	}

	if err := p.repo.SavePasskeyChallenge(ctx, challenge); err != nil {
		return nil, fmt.Errorf("passkey: failed to save registration challenge: %w", err)
	}

	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(EventRegistrationOptionsCreated, RegistrationOptionsCreatedPayload{
			UserID:         userID,
			UserName:       userName,
			ChallengeToken: token,
			ExpiresAt:      expiresAt,
			Extra:          params.Extra,
			Timestamp:      time.Now(),
		})
	}

	return &RegistrationOptionsResult{
		Options:        creation,
		ChallengeToken: token,
		ExpiresAt:      expiresAt,
	}, nil
}

// VerifyRegistration verifies the response from navigator.credentials.create() and registers the passkey.
func (p *Plugin) VerifyRegistration(ctx context.Context, params *VerifyRegistrationParams) (*entity.Passkey, error) {
	p.mu.RLock()
	w := p.webauthn
	p.mu.RUnlock()

	if w == nil {
		return nil, fmt.Errorf("passkey: plugin not initialized")
	}

	if params == nil || params.ChallengeToken == "" || params.Response == nil {
		return nil, ErrInvalidParameter
	}

	challenge, err := p.repo.ConsumePasskeyChallenge(ctx, params.ChallengeToken)
	if err != nil || challenge == nil {
		return nil, ErrChallengeNotFound
	}

	if time.Now().After(challenge.ExpiresAt) {
		p.publishRegistrationFailed(challenge.UserID, params.ChallengeToken, "challenge expired", params.Extra)
		return nil, ErrChallengeExpired
	}

	if challenge.Type != CeremonyRegistration {
		p.publishRegistrationFailed(challenge.UserID, params.ChallengeToken, "invalid ceremony type", params.Extra)
		return nil, ErrInvalidCeremonyType
	}

	var sessionData webauthn.SessionData
	if err := json.Unmarshal([]byte(challenge.SessionData), &sessionData); err != nil {
		p.publishRegistrationFailed(challenge.UserID, params.ChallengeToken, "corrupted challenge session", params.Extra)
		return nil, fmt.Errorf("passkey: invalid stored challenge session data: %w", err)
	}

	userID := ""
	if challenge.UserID != nil {
		userID = *challenge.UserID
	}
	userName := ""
	if challenge.UserName != nil {
		userName = *challenge.UserName
	}
	displayName := ""
	if challenge.DisplayName != nil {
		displayName = *challenge.DisplayName
	}

	if params.CallerUserID != nil && *params.CallerUserID != "" && *params.CallerUserID != userID {
		p.publishRegistrationFailed(&userID, params.ChallengeToken, "caller user mismatch", params.Extra)
		return nil, ErrUnauthorized
	}

	existingPasskeys, _ := p.repo.ListPasskeysByUserID(ctx, userID)
	webUser := buildWebAuthnUser(userID, userName, displayName, existingPasskeys)

	respBytes, err := json.Marshal(params.Response)
	if err != nil {
		p.publishRegistrationFailed(&userID, params.ChallengeToken, "malformed response body", params.Extra)
		return nil, fmt.Errorf("%w: %v", ErrInvalidParameter, err)
	}

	parsedResponse, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(respBytes))
	if err != nil {
		p.publishRegistrationFailed(&userID, params.ChallengeToken, fmt.Sprintf("parse error: %v", err), params.Extra)
		return nil, fmt.Errorf("%w: %v", ErrVerificationFailed, err)
	}

	cred, err := w.CreateCredential(webUser, sessionData, parsedResponse)
	if err != nil {
		p.publishRegistrationFailed(&userID, params.ChallengeToken, fmt.Sprintf("verification failed: %v", err), params.Extra)
		return nil, fmt.Errorf("%w: %v", ErrVerificationFailed, err)
	}

	credIDStr := base64.RawURLEncoding.EncodeToString(cred.ID)

	// Check if already registered
	if existing, _ := p.repo.GetPasskeyByCredentialID(ctx, credIDStr); existing != nil {
		p.publishRegistrationFailed(&userID, params.ChallengeToken, "credential already exists", params.Extra)
		return nil, ErrPasskeyAlreadyExists
	}

	pubKeyStr := base64.StdEncoding.EncodeToString(cred.PublicKey)
	aaguidStr := formatAAGUID(cred.Authenticator.AAGUID)

	var name string
	if params.Name != nil && strings.TrimSpace(*params.Name) != "" {
		name = strings.TrimSpace(*params.Name)
	} else {
		name = GetAuthenticatorName(&aaguidStr)
	}

	deviceType := "singleDevice"
	if cred.Flags.BackupEligible || cred.Flags.BackupState {
		deviceType = "multiDevice"
	}

	var transportsStr *string
	if len(cred.Transport) > 0 {
		var tStrings []string
		for _, t := range cred.Transport {
			tStrings = append(tStrings, string(t))
		}
		joined := strings.Join(tStrings, ",")
		transportsStr = &joined
	}

	passkeyID, err := generateRandomHex(16)
	if err != nil {
		return nil, fmt.Errorf("passkey: failed to generate passkey id: %w", err)
	}

	now := time.Now()
	newPasskey := &entity.Passkey{
		ID:           "pk_" + passkeyID,
		Name:         &name,
		UserID:       userID,
		CredentialID: credIDStr,
		PublicKey:    pubKeyStr,
		Counter:      uint32(cred.Authenticator.SignCount),
		DeviceType:   deviceType,
		BackedUp:     cred.Flags.BackupState,
		Transports:   transportsStr,
		AAGUID:       &aaguidStr,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := p.repo.CreatePasskey(ctx, newPasskey); err != nil {
		return nil, fmt.Errorf("passkey: failed to persist passkey: %w", err)
	}

	var userEntity *entity.User
	if u, err := p.repo.GetUserByID(ctx, userID); err == nil {
		userEntity = u
	}

	if p.config.AfterRegistration != nil {
		if err := p.config.AfterRegistration(ctx, newPasskey, userEntity); err != nil {
			// Hook failed - log but proceed
		}
	}

	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(EventRegistrationVerified, RegistrationVerifiedPayload{
			Passkey:   newPasskey,
			User:      userEntity,
			Extra:     params.Extra,
			Timestamp: now,
		})
	}

	return newPasskey, nil
}

// GenerateAuthenticationOptions begins a WebAuthn assertion ceremony for signing in.
func (p *Plugin) GenerateAuthenticationOptions(ctx context.Context, params *GenerateAuthenticationOptionsParams) (*AuthenticationOptionsResult, error) {
	p.mu.RLock()
	w := p.webauthn
	p.mu.RUnlock()

	if w == nil {
		return nil, fmt.Errorf("passkey: plugin not initialized")
	}

	if params == nil {
		params = &GenerateAuthenticationOptionsParams{}
	}

	var assertion *protocol.CredentialAssertion
	var sessionData *webauthn.SessionData
	var err error
	var targetUserID *string

	if params.UserID != nil && *params.UserID != "" {
		targetUserID = params.UserID
		passkeys, _ := p.repo.ListPasskeysByUserID(ctx, *params.UserID)
		userName := *params.UserID
		if u, err := p.repo.GetUserByID(ctx, *params.UserID); err == nil && u != nil {
			userName = u.Email
		}
		webUser := buildWebAuthnUser(*params.UserID, userName, userName, passkeys)
		assertion, sessionData, err = w.BeginLogin(webUser)
	} else {
		// Discoverable / resident key login
		assertion, sessionData, err = w.BeginDiscoverableLogin()
	}

	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrVerificationFailed, err)
	}

	sessionBytes, err := json.Marshal(sessionData)
	if err != nil {
		return nil, fmt.Errorf("passkey: failed to serialize assertion session data: %w", err)
	}

	token, err := generateRandomHex(32)
	if err != nil {
		return nil, fmt.Errorf("passkey: failed to generate challenge token: %w", err)
	}

	expiresAt := time.Now().Add(p.config.ChallengeTimeout)
	challenge := &PasskeyChallenge{
		Token:       token,
		Type:        CeremonyAuthentication,
		Challenge:   sessionData.Challenge,
		UserID:      targetUserID,
		SessionData: string(sessionBytes),
		ExpiresAt:   expiresAt,
		CreatedAt:   time.Now(),
	}

	if err := p.repo.SavePasskeyChallenge(ctx, challenge); err != nil {
		return nil, fmt.Errorf("passkey: failed to save authentication challenge: %w", err)
	}

	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(EventAuthenticationOptionsCreated, AuthenticationOptionsCreatedPayload{
			UserID:         targetUserID,
			ChallengeToken: token,
			ExpiresAt:      expiresAt,
			Extra:          params.Extra,
			Timestamp:      time.Now(),
		})
	}

	return &AuthenticationOptionsResult{
		Options:        assertion,
		ChallengeToken: token,
		ExpiresAt:      expiresAt,
	}, nil
}

// VerifyAuthentication verifies a WebAuthn assertion response and issues an authenticated session.
func (p *Plugin) VerifyAuthentication(ctx context.Context, params *VerifyAuthenticationParams) (*VerifyAuthenticationResult, error) {
	p.mu.RLock()
	w := p.webauthn
	p.mu.RUnlock()

	if w == nil {
		return nil, fmt.Errorf("passkey: plugin not initialized")
	}

	if params == nil || params.ChallengeToken == "" || params.Response == nil {
		return nil, ErrInvalidParameter
	}

	challenge, err := p.repo.ConsumePasskeyChallenge(ctx, params.ChallengeToken)
	if err != nil || challenge == nil {
		return nil, ErrChallengeNotFound
	}

	if time.Now().After(challenge.ExpiresAt) {
		p.publishAuthenticationFailed(challenge.UserID, params.ChallengeToken, "challenge expired", params.Extra)
		return nil, ErrChallengeExpired
	}

	if challenge.Type != CeremonyAuthentication {
		p.publishAuthenticationFailed(challenge.UserID, params.ChallengeToken, "invalid ceremony type", params.Extra)
		return nil, ErrInvalidCeremonyType
	}

	var sessionData webauthn.SessionData
	if err := json.Unmarshal([]byte(challenge.SessionData), &sessionData); err != nil {
		p.publishAuthenticationFailed(challenge.UserID, params.ChallengeToken, "corrupted challenge session", params.Extra)
		return nil, fmt.Errorf("passkey: invalid stored challenge session data: %w", err)
	}

	respBytes, err := json.Marshal(params.Response)
	if err != nil {
		p.publishAuthenticationFailed(challenge.UserID, params.ChallengeToken, "malformed response body", params.Extra)
		return nil, fmt.Errorf("%w: %v", ErrInvalidParameter, err)
	}

	parsedResponse, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(respBytes))
	if err != nil {
		p.publishAuthenticationFailed(challenge.UserID, params.ChallengeToken, fmt.Sprintf("parse error: %v", err), params.Extra)
		return nil, fmt.Errorf("%w: %v", ErrVerificationFailed, err)
	}

	var storedPasskey *entity.Passkey
	var userEntity *entity.User

	if challenge.UserID != nil && *challenge.UserID != "" {
		userID := *challenge.UserID
		u, err := p.repo.GetUserByID(ctx, userID)
		if err != nil || u == nil {
			p.publishAuthenticationFailed(&userID, params.ChallengeToken, "user not found", params.Extra)
			return nil, ErrUserNotFound
		}
		userEntity = u

		userPasskeys, _ := p.repo.ListPasskeysByUserID(ctx, userID)
		webUser := buildWebAuthnUser(userID, u.Email, u.Name, userPasskeys)

		cred, err := w.ValidateLogin(webUser, sessionData, parsedResponse)
		if err != nil {
			p.publishAuthenticationFailed(&userID, params.ChallengeToken, fmt.Sprintf("assertion verification failed: %v", err), params.Extra)
			return nil, fmt.Errorf("%w: %v", ErrVerificationFailed, err)
		}

		credIDStr := base64.RawURLEncoding.EncodeToString(cred.ID)
		for _, pk := range userPasskeys {
			if pk.CredentialID == credIDStr {
				storedPasskey = pk
				break
			}
		}
		if storedPasskey == nil {
			storedPasskey, _ = p.findPasskeyByFlexibleID(ctx, cred.ID)
		}
	} else {
		// Discoverable login: locate passkey by credential ID
		pk, err := p.findPasskeyByFlexibleID(ctx, parsedResponse.RawID)
		if err != nil || pk == nil {
			p.publishAuthenticationFailed(nil, params.ChallengeToken, "passkey not found", params.Extra)
			return nil, ErrPasskeyNotFound
		}
		storedPasskey = pk

		u, err := p.repo.GetUserByID(ctx, storedPasskey.UserID)
		if err != nil || u == nil {
			p.publishAuthenticationFailed(&storedPasskey.UserID, params.ChallengeToken, "user not found", params.Extra)
			return nil, ErrUserNotFound
		}
		userEntity = u

		userPasskeys, _ := p.repo.ListPasskeysByUserID(ctx, u.ID)
		webUser := buildWebAuthnUser(u.ID, u.Email, u.Name, userPasskeys)

		userHandler := func(rawID, userHandle []byte) (webauthn.User, error) {
			return webUser, nil
		}

		_, err = w.ValidateDiscoverableLogin(userHandler, sessionData, parsedResponse)
		if err != nil {
			p.publishAuthenticationFailed(&u.ID, params.ChallengeToken, fmt.Sprintf("discoverable verification failed: %v", err), params.Extra)
			return nil, fmt.Errorf("%w: %v", ErrVerificationFailed, err)
		}
	}

	if storedPasskey == nil {
		p.publishAuthenticationFailed(&userEntity.ID, params.ChallengeToken, "matching passkey not found", params.Extra)
		return nil, ErrPasskeyNotFound
	}

	// Counter validation & Clone detection:
	// If counter is enabled (>0) and received counter is less than or equal to stored counter, reject as possible clone.
	receivedCounter := parsedResponse.Response.AuthenticatorData.Flags.HasUserVerified()
	_ = receivedCounter
	signCount := parsedResponse.Response.AuthenticatorData.Counter

	if signCount > 0 && signCount <= storedPasskey.Counter {
		p.publishAuthenticationFailed(&userEntity.ID, params.ChallengeToken, "counter did not increment", params.Extra)
		return nil, ErrCounterNotIncremented
	}

	// Update counter in repository
	if signCount > storedPasskey.Counter {
		_ = p.repo.UpdatePasskeyCounter(ctx, storedPasskey.ID, signCount)
		storedPasskey.Counter = signCount
	}

	// Update backup state if changed
	isBackedUp := parsedResponse.Response.AuthenticatorData.Flags.HasBackupState()
	if isBackedUp != storedPasskey.BackedUp {
		storedPasskey.BackedUp = isBackedUp
		storedPasskey.UpdatedAt = time.Now()
		_ = p.repo.UpdatePasskey(ctx, storedPasskey)
	}

	// Create user session
	sessionToken, err := generateRandomHex(32)
	if err != nil {
		return nil, fmt.Errorf("passkey: failed to generate session token: %w", err)
	}

	ipAddress := ""
	userAgent := ""
	if params.Extra != nil {
		if ip, ok := params.Extra[ExtraKeyIPAddress].(string); ok {
			ipAddress = ip
		}
		if ua, ok := params.Extra[ExtraKeyUserAgent].(string); ok {
			userAgent = ua
		}
	}

	now := time.Now()
	sessionParams := &dto.CreateSessionParams{
		UserID:    userEntity.ID,
		Token:     sessionToken,
		IPAddress: ipAddress,
		UserAgent: userAgent,
		ExpiresAt: now.Add(p.config.SessionDuration),
		CreatedAt:      now,
		ExtraContainer: params.ExtraContainer,
	}

	session, err := p.repo.CreateSession(ctx, sessionParams)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnableToCreateSession, err)
	}

	if p.config.AfterAuthentication != nil {
		if err := p.config.AfterAuthentication(ctx, storedPasskey, userEntity, session); err != nil {
			// Hook failed - proceed with session
		}
	}

	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(EventAuthenticationVerified, AuthenticationVerifiedPayload{
			Passkey:   storedPasskey,
			User:      userEntity,
			Session:   session,
			Extra:     params.Extra,
			Timestamp: now,
		})
	}

	return &VerifyAuthenticationResult{
		User:    userEntity,
		Session: session,
		Passkey: storedPasskey,
	}, nil
}

// ListPasskeys retrieves all passkeys associated with a user.
func (p *Plugin) ListPasskeys(ctx context.Context, params *ListPasskeysParams) ([]*entity.Passkey, error) {
	if params == nil || params.UserID == "" {
		return nil, ErrInvalidParameter
	}
	return p.repo.ListPasskeysByUserID(ctx, params.UserID)
}

// UpdatePasskey modifies a passkey's friendly name after verifying ownership.
func (p *Plugin) UpdatePasskey(ctx context.Context, params *UpdatePasskeyParams) (*entity.Passkey, error) {
	if params == nil || params.ID == "" || params.CallerUserID == "" {
		return nil, ErrInvalidParameter
	}

	pk, err := p.repo.GetPasskeyByID(ctx, params.ID)
	if err != nil || pk == nil {
		return nil, ErrPasskeyNotFound
	}

	if pk.UserID != params.CallerUserID {
		return nil, ErrUnauthorized
	}

	oldName := pk.Name
	newName := strings.TrimSpace(params.Name)
	if newName == "" {
		newName = GetAuthenticatorName(pk.AAGUID)
	}
	pk.Name = &newName
	pk.UpdatedAt = time.Now()

	if err := p.repo.UpdatePasskey(ctx, pk); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFailedToUpdatePasskey, err)
	}

	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(EventPasskeyUpdated, PasskeyUpdatedPayload{
			Passkey:   pk,
			OldName:   oldName,
			NewName:   newName,
			Timestamp: time.Now(),
		})
	}

	return pk, nil
}

// DeletePasskey removes a passkey after verifying caller ownership.
func (p *Plugin) DeletePasskey(ctx context.Context, params *DeletePasskeyParams) error {
	if params == nil || params.ID == "" || params.CallerUserID == "" {
		return ErrInvalidParameter
	}

	pk, err := p.repo.GetPasskeyByID(ctx, params.ID)
	if err != nil || pk == nil {
		return ErrPasskeyNotFound
	}

	if pk.UserID != params.CallerUserID {
		return ErrUnauthorized
	}

	if err := p.repo.DeletePasskey(ctx, params.ID); err != nil {
		return fmt.Errorf("passkey: failed to delete passkey: %w", err)
	}

	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(EventPasskeyDeleted, PasskeyDeletedPayload{
			PasskeyID: params.ID,
			UserID:    params.CallerUserID,
			Timestamp: time.Now(),
		})
	}

	return nil
}

// GetPasskey retrieves a single passkey by its unique identifier.
func (p *Plugin) GetPasskey(ctx context.Context, id string) (*entity.Passkey, error) {
	if id == "" {
		return nil, ErrInvalidParameter
	}
	return p.repo.GetPasskeyByID(ctx, id)
}

// Helper methods

func (p *Plugin) findPasskeyByFlexibleID(ctx context.Context, rawID []byte) (*entity.Passkey, error) {
	// Try raw URL base64
	id1 := base64.RawURLEncoding.EncodeToString(rawID)
	if pk, err := p.repo.GetPasskeyByCredentialID(ctx, id1); err == nil && pk != nil {
		return pk, nil
	}

	// Try URL base64
	id2 := base64.URLEncoding.EncodeToString(rawID)
	if pk, err := p.repo.GetPasskeyByCredentialID(ctx, id2); err == nil && pk != nil {
		return pk, nil
	}

	// Try Std base64
	id3 := base64.StdEncoding.EncodeToString(rawID)
	if pk, err := p.repo.GetPasskeyByCredentialID(ctx, id3); err == nil && pk != nil {
		return pk, nil
	}

	return nil, ErrPasskeyNotFound
}

func (p *Plugin) publishRegistrationFailed(userID *string, challengeToken, reason string, extra map[string]any) {
	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(EventRegistrationFailed, RegistrationFailedPayload{
			UserID:         userID,
			ChallengeToken: challengeToken,
			Reason:         reason,
			Extra:          extra,
			Timestamp:      time.Now(),
		})
	}
}

func (p *Plugin) publishAuthenticationFailed(userID *string, challengeToken, reason string, extra map[string]any) {
	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(EventAuthenticationFailed, AuthenticationFailedPayload{
			UserID:         userID,
			ChallengeToken: challengeToken,
			Reason:         reason,
			Extra:          extra,
			Timestamp:      time.Now(),
		})
	}
}

func generateRandomHex(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
