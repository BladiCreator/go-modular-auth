package providers

import (
	"fmt"
	"strings"

	"github.com/BladiCreator/go-modular-auth/plugins/genericoauth"
)

// OktaOptions defines configuration parameters for Okta OAuth2/OIDC.
type OktaOptions struct {
	Domain       string
	ClientID     string
	ClientSecret string
	Scopes       []string
	RedirectURI  string
	PKCE         bool
}

// Okta constructs a ProviderConfig configured for Okta authentication.
func Okta(opts OktaOptions) *genericoauth.ProviderConfig {
	domain := strings.TrimPrefix(strings.TrimPrefix(opts.Domain, "https://"), "http://")
	discoveryURL := fmt.Sprintf("https://%s/.well-known/openid-configuration", domain)

	scopes := opts.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}

	return &genericoauth.ProviderConfig{
		ProviderID:   "okta",
		DiscoveryURL: discoveryURL,
		ClientID:     opts.ClientID,
		ClientSecret: opts.ClientSecret,
		Scopes:       scopes,
		RedirectURI:  opts.RedirectURI,
		PKCE:         opts.PKCE,
	}
}
