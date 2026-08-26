package genericoauth

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"strings"
)

// OIDCDiscoveryDocument represents the metadata returned by .well-known/openid-configuration.
type OIDCDiscoveryDocument struct {
	Issuer                string   `json:"issuer"`
	AuthorizationEndpoint string   `json:"authorization_endpoint"`
	TokenEndpoint         string   `json:"token_endpoint"`
	UserInfoEndpoint      string   `json:"userinfo_endpoint"`
	JWKSURI               string   `json:"jwks_uri"`
	ScopesSupported       []string `json:"scopes_supported,omitempty"`
}

// FetchDiscovery retrieves and parses the OpenID Connect discovery document from the specified discovery URL.
func FetchDiscovery(ctx context.Context, client *http.Client, discoveryURL string, headers http.Header) (*OIDCDiscoveryDocument, error) {
	if client == nil {
		client = http.DefaultClient
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create discovery request: %w", err)
	}

	maps.Copy(req.Header, headers)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("discovery request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("discovery request returned non-200 status: %d", resp.StatusCode)
	}

	var doc OIDCDiscoveryDocument
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, fmt.Errorf("failed to decode discovery document: %w", err)
	}

	return &doc, nil
}

// ResolveProviderConfig populates missing AuthorizationURL, TokenURL, UserInfoURL, and Issuer from discovery if discoveryURL is provided.
func ResolveProviderConfig(ctx context.Context, client *http.Client, cfg *ProviderConfig) error {
	if cfg.DiscoveryURL == "" {
		return nil
	}

	doc, err := FetchDiscovery(ctx, client, cfg.DiscoveryURL, cfg.DiscoveryHeaders)
	if err != nil {
		return err
	}

	if cfg.RequireIssuerValidation && cfg.Issuer != "" && !strings.EqualFold(strings.TrimSuffix(cfg.Issuer, "/"), strings.TrimSuffix(doc.Issuer, "/")) {
		return fmt.Errorf("%w: expected %s, got %s", ErrIssuerMismatch, cfg.Issuer, doc.Issuer)
	}

	if cfg.Issuer == "" {
		cfg.Issuer = doc.Issuer
	}
	if cfg.AuthorizationURL == "" {
		cfg.AuthorizationURL = doc.AuthorizationEndpoint
	}
	if cfg.TokenURL == "" {
		cfg.TokenURL = doc.TokenEndpoint
	}
	if cfg.UserInfoURL == "" {
		cfg.UserInfoURL = doc.UserInfoEndpoint
	}

	return nil
}
