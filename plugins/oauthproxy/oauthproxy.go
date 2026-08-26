package oauthproxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/BladiCreator/go-modular-auth/plugin"
)

// PluginID is the unique string identifier for the OAuth Proxy plugin ("oauth-proxy").
const PluginID = "oauth-proxy"

var (
	ErrExpiredPayload = errors.New("oauthproxy: payload has expired beyond max age")
	ErrClockSkew      = errors.New("oauthproxy: payload timestamp is in the future beyond allowed tolerance")
)

// Plugin implements the OAuth Proxy plugin for go-modular-auth.
type Plugin struct {
	config Config
	ctx    *plugin.Context
}

// New creates a new OAuth Proxy plugin instance configured with options.
func New(opts ...Option) *Plugin {
	cfg := DefaultConfig()
	for _, opt := range opts {
		opt(&cfg)
	}
	return &Plugin{
		config: cfg,
	}
}

// ID returns the unique identifier for the OAuth Proxy plugin ("oauth-proxy").
func (p *Plugin) ID() string {
	return PluginID
}

// Init initializes the plugin with the shared execution context.
func (p *Plugin) Init(ctx *plugin.Context) error {
	p.ctx = ctx
	return nil
}

// Config returns the active configuration of the OAuth Proxy plugin.
func (p *Plugin) Config() Config {
	return p.config
}

// CreateStatePackage serializes and encrypts a StatePackage struct into a URL-safe Base64 string.
func (p *Plugin) CreateStatePackage(state, callbackURL, currentURL string) (string, error) {
	pkg := StatePackage{
		State:       state,
		CallbackURL: callbackURL,
		CurrentURL:  currentURL,
		CreatedAt:   time.Now().UnixMilli(),
	}

	data, err := json.Marshal(pkg)
	if err != nil {
		return "", fmt.Errorf("oauthproxy: failed to marshal state package: %w", err)
	}

	return Encrypt(p.config.Secret, data)
}

// ParseStatePackage decrypts and deserializes an encrypted state parameter into a StatePackage struct.
func (p *Plugin) ParseStatePackage(encryptedState string) (*StatePackage, error) {
	data, err := Decrypt(p.config.Secret, encryptedState)
	if err != nil {
		return nil, fmt.Errorf("oauthproxy: failed to decrypt state package: %w", err)
	}

	var pkg StatePackage
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil, fmt.Errorf("oauthproxy: failed to unmarshal state package: %w", err)
	}

	return &pkg, nil
}

// CreatePassthroughPayload serializes and encrypts a PassthroughPayload struct into a URL-safe Base64 string.
func (p *Plugin) CreatePassthroughPayload(payload *PassthroughPayload) (string, error) {
	if payload.Timestamp == 0 {
		payload.Timestamp = time.Now().UnixMilli()
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("oauthproxy: failed to marshal passthrough payload: %w", err)
	}

	return Encrypt(p.config.Secret, data)
}

// ParsePassthroughPayload decrypts, deserializes, and validates the MaxAge and anti-replay timestamp of a profile payload.
func (p *Plugin) ParsePassthroughPayload(encryptedPayload string) (*PassthroughPayload, error) {
	data, err := Decrypt(p.config.Secret, encryptedPayload)
	if err != nil {
		return nil, fmt.Errorf("oauthproxy: failed to decrypt passthrough payload: %w", err)
	}

	var payload PassthroughPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil, fmt.Errorf("oauthproxy: failed to unmarshal passthrough payload: %w", err)
	}

	// Validate MaxAge timestamp
	now := time.Now().UnixMilli()
	diff := now - payload.Timestamp

	// Clock skew tolerance: allow up to 10 seconds in the future
	if diff < -10000 {
		return nil, ErrClockSkew
	}

	if p.config.MaxAge > 0 && diff > p.config.MaxAge.Milliseconds() {
		return nil, ErrExpiredPayload
	}

	return &payload, nil
}
