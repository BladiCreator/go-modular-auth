package magiclink

import (
	"context"
	"encoding/json"
	"net/mail"
	"net/url"
	"strings"
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/dto"
	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/BladiCreator/go-modular-auth/plugin"
	"github.com/google/uuid"
)

// PluginID is the unique string identifier for the Magic Link plugin ("magic-link").
const PluginID = "magic-link"

// Plugin implements the magic link authentication plugin for go-modular-auth.
type Plugin struct {
	repo   Repository
	config Config
	ctx    *plugin.Context
	hasher Hasher
	cipher Cipher
}

// New instantiates a new Magic Link plugin configured with the given repository and options.
func New(repo Repository, opts ...Option) *Plugin {
	cfg := DefaultConfig()
	for _, opt := range opts {
		opt(&cfg)
	}

	p := &Plugin{
		repo:   repo,
		config: cfg,
	}

	if cfg.CustomHasher != nil {
		p.hasher = cfg.CustomHasher
	} else {
		p.hasher = DefaultSHA256Hasher{}
	}

	if cfg.CustomCipher != nil {
		p.cipher = cfg.CustomCipher
	} else if cfg.SecretKey != "" {
		if ciph, err := NewAESGCMCipher(cfg.SecretKey); err == nil {
			p.cipher = ciph
		}
	}

	return p
}

// ID returns the unique identifier string for the plugin.
func (p *Plugin) ID() string {
	return PluginID
}

// Init initializes the plugin with the shared execution context.
func (p *Plugin) Init(ctx *plugin.Context) error {
	p.ctx = ctx
	return nil
}

// publishEvent safely emits an event to the shared event bus if available.
func (p *Plugin) publishEvent(topic string, payload any) {
	if p.ctx != nil && p.ctx.Events() != nil {
		p.ctx.Events().Publish(topic, payload)
	}
}

// SignInMagicLink generates a secure token, saves the verification record, and dispatches the magic link email.
func (p *Plugin) SignInMagicLink(ctx context.Context, params SignInMagicLinkParams) (*SignInMagicLinkResult, error) {
	email := strings.ToLower(strings.TrimSpace(params.Email))
	if email == "" {
		return nil, ErrInvalidEmail
	}
	if _, err := mail.ParseAddress(email); err != nil {
		return nil, ErrInvalidEmail
	}

	if p.config.SendMagicLink == nil {
		return nil, ErrSendCallbackMissing
	}

	var token string
	var err error
	if p.config.GenerateToken != nil {
		token, err = p.config.GenerateToken(ctx, email)
	} else {
		token, err = DefaultTokenGenerator(32)
	}
	if err != nil {
		return nil, err
	}

	storedToken, err := p.storeToken(token)
	if err != nil {
		return nil, err
	}

	expiresAt := time.Now().Add(p.config.ExpiresIn)
	payload := TokenPayload{
		Token:              storedToken,
		Email:              email,
		Name:               params.Name,
		CallbackURL:        params.CallbackURL,
		NewUserCallbackURL: params.NewUserCallbackURL,
		ErrorCallbackURL:   params.ErrorCallbackURL,
		Extra:              params.Extra,
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	identifier := ToMagicLinkIdentifier(email)
	record := &VerificationRecord{
		ID:         uuid.NewString(),
		Identifier: identifier,
		Value:      string(payloadBytes),
		ExpiresAt:  expiresAt,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	_ = p.repo.DeleteVerificationValue(ctx, identifier)
	if err := p.repo.CreateVerificationValue(ctx, record); err != nil {
		return nil, err
	}

	// Also store reverse token lookup mapping for token-only resolution
	tokenLookupKey := ToMagicLinkTokenLookupKey(token)
	lookupRecord := &VerificationRecord{
		ID:         uuid.NewString(),
		Identifier: tokenLookupKey,
		Value:      email,
		ExpiresAt:  expiresAt,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}
	_ = p.repo.DeleteVerificationValue(ctx, tokenLookupKey)
	_ = p.repo.CreateVerificationValue(ctx, lookupRecord)

	// Build verification URL with query parameters
	baseURL := p.config.DefaultCallbackURL
	if baseURL == "" {
		baseURL = "/"
	}
	parsedURL, parseErr := url.Parse(baseURL)
	if parseErr != nil {
		parsedURL = &url.URL{Path: "/magic-link/verify"}
	} else if !strings.HasSuffix(parsedURL.Path, "/verify") {
		parsedURL.Path = "/magic-link/verify"
	}

	q := parsedURL.Query()
	q.Set("token", token)
	q.Set("email", email)
	if params.CallbackURL != "" {
		q.Set("callbackURL", params.CallbackURL)
	}
	if params.NewUserCallbackURL != "" {
		q.Set("newUserCallbackURL", params.NewUserCallbackURL)
	}
	if params.ErrorCallbackURL != "" {
		q.Set("errorCallbackURL", params.ErrorCallbackURL)
	}
	parsedURL.RawQuery = q.Encode()

	sendData := SendMagicLinkData{
		Email:              email,
		Name:               params.Name,
		URL:                parsedURL.String(),
		Token:              token,
		CallbackURL:        params.CallbackURL,
		NewUserCallbackURL: params.NewUserCallbackURL,
		ErrorCallbackURL:   params.ErrorCallbackURL,
		Extra:              params.Extra,
	}

	p.publishEvent(EventMagicLinkSendBefore, &SendMagicLinkPendingPayload{
		Email:     email,
		URL:       sendData.URL,
		ExpiresAt: expiresAt,
		Extra:     params.Extra,
	})

	if err := p.config.SendMagicLink(ctx, sendData); err != nil {
		return nil, err
	}

	p.publishEvent(EventMagicLinkSent, &MagicLinkSentPayload{
		Email:     email,
		URL:       sendData.URL,
		ExpiresAt: expiresAt,
		Extra:     params.Extra,
	})

	return &SignInMagicLinkResult{
		Success:   true,
		ExpiresAt: expiresAt,
	}, nil
}

// VerifyMagicLink verifies the token atómicamente, authenticates or registers the user, and creates a session.
func (p *Plugin) VerifyMagicLink(ctx context.Context, params VerifyMagicLinkParams) (*VerifyMagicLinkResult, error) {
	token := strings.TrimSpace(params.Token)
	if token == "" {
		return nil, ErrInvalidToken
	}

	p.publishEvent(EventMagicLinkVerifyBefore, &VerifyBeforePayload{
		Token: token,
		Extra: params.Extra,
	})

	email := strings.ToLower(strings.TrimSpace(params.Email))
	if email == "" {
		// Reverse token lookup if email wasn't provided in params
		tokenLookupKey := ToMagicLinkTokenLookupKey(token)
		lookupRecord, err := p.repo.FindVerificationValue(ctx, tokenLookupKey)
		if err == nil && lookupRecord != nil && !lookupRecord.ExpiresAt.Before(time.Now()) {
			email = lookupRecord.Value
			_ = p.repo.DeleteVerificationValue(ctx, tokenLookupKey)
		}
	} else {
		_ = p.repo.DeleteVerificationValue(ctx, ToMagicLinkTokenLookupKey(token))
	}

	if email == "" {
		p.publishEvent(EventMagicLinkFailed, &MagicLinkFailedPayload{
			Token:  token,
			Reason: "missing_email_or_token_lookup_failed",
			Extra:  params.Extra,
		})
		return nil, ErrInvalidToken
	}

	identifier := ToMagicLinkIdentifier(email)
	payload, err := p.atomicConsumeToken(ctx, identifier, token, params.Extra)
	if err != nil {
		return nil, err
	}

	user, err := p.repo.FindUserByEmail(ctx, email)
	isNewUser := false

	if err != nil || user == nil {
		if p.config.DisableSignUp {
			p.publishEvent(EventMagicLinkFailed, &MagicLinkFailedPayload{
				Email:  email,
				Token:  token,
				Reason: "signup_disabled",
				Extra:  params.Extra,
			})
			return nil, ErrSignUpDisabled
		}

		userName := payload.Name
		if userName == "" {
			parts := strings.Split(email, "@")
			userName = parts[0]
		}

		newUser := &entity.User{
			ID:            uuid.NewString(),
			Name:          userName,
			Email:         email,
			EmailVerified: true,
			CreatedAt:     time.Now(),
			UpdatedAt:     time.Now(),
		}

		user, err = p.repo.CreateUser(ctx, newUser)
		if err != nil {
			return nil, err
		}
		isNewUser = true
	} else {
		if !user.EmailVerified {
			_ = p.repo.UpdateEmailVerified(ctx, user.ID, true)
			user.EmailVerified = true
		}
	}

	sessionParams := &dto.CreateSessionParams{
		UserID:    user.ID,
		Token:     uuid.NewString(),
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour),
		CreatedAt: time.Now(),
	}

	session, err := p.repo.CreateSession(ctx, sessionParams)
	if err != nil {
		return nil, err
	}

	// Determine final redirect URL
	redirectURL := params.CallbackURL
	if redirectURL == "" {
		redirectURL = payload.CallbackURL
	}
	if isNewUser {
		if params.NewUserCallbackURL != "" {
			redirectURL = params.NewUserCallbackURL
		} else if payload.NewUserCallbackURL != "" {
			redirectURL = payload.NewUserCallbackURL
		}
	}
	if redirectURL == "" {
		redirectURL = p.config.DefaultCallbackURL
	}
	if redirectURL == "" {
		redirectURL = "/"
	}

	p.publishEvent(EventMagicLinkVerified, &MagicLinkVerifiedPayload{
		Email:     email,
		User:      user,
		IsNewUser: isNewUser,
	})

	p.publishEvent(EventMagicLinkSignInSuccess, &SignInSuccessPayload{
		User:      user,
		Session:   session,
		IsNewUser: isNewUser,
	})

	return &VerifyMagicLinkResult{
		User:        user,
		Session:     session,
		IsNewUser:   isNewUser,
		RedirectURL: redirectURL,
	}, nil
}
