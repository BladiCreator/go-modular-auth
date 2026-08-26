package providers

import (
	"fmt"
	"strings"

	"github.com/BladiCreator/go-modular-auth/plugins/genericoauth"
)

// KeycloakOptions defines configuration parameters for Keycloak OIDC.
type KeycloakOptions struct {
	BaseURL      string
	Realm        string
	ClientID     string
	ClientSecret string
	Scopes       []string
	RedirectURI  string
	PKCE         bool
}

// Keycloak constructs a ProviderConfig configured for Keycloak realm authentication.
func Keycloak(opts KeycloakOptions) *genericoauth.ProviderConfig {
	baseURL := strings.TrimSuffix(opts.BaseURL, "/")
	discoveryURL := fmt.Sprintf("%s/realms/%s/.well-known/openid-configuration", baseURL, opts.Realm)

	scopes := opts.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}

	return &genericoauth.ProviderConfig{
		ProviderID:   "keycloak",
		DiscoveryURL: discoveryURL,
		ClientID:     opts.ClientID,
		ClientSecret: opts.ClientSecret,
		Scopes:       scopes,
		RedirectURI:  opts.RedirectURI,
		PKCE:         opts.PKCE,
	}
}
