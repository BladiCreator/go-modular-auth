package providers

import (
	"fmt"
	"strings"

	"github.com/BladiCreator/go-modular-auth/plugins/genericoauth"
)

// Auth0Options defines configuration parameters for Auth0 OAuth2/OIDC.
type Auth0Options struct {
	Domain       string
	ClientID     string
	ClientSecret string
	Scopes       []string
	RedirectURI  string
	PKCE         bool
}

// Auth0 constructs a ProviderConfig configured for Auth0 authentication.
func Auth0(opts Auth0Options) *genericoauth.ProviderConfig {
	domain := strings.TrimPrefix(strings.TrimPrefix(opts.Domain, "https://"), "http://")
	discoveryURL := fmt.Sprintf("https://%s/.well-known/openid-configuration", domain)

	scopes := opts.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}

	return &genericoauth.ProviderConfig{
		ProviderID:   "auth0",
		DiscoveryURL: discoveryURL,
		ClientID:     opts.ClientID,
		ClientSecret: opts.ClientSecret,
		Scopes:       scopes,
		RedirectURI:  opts.RedirectURI,
		PKCE:         opts.PKCE,
	}
}
