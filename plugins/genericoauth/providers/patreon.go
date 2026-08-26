package providers

import (
	"github.com/BladiCreator/go-modular-auth/plugins/genericoauth"
)

// PatreonOptions defines configuration parameters for Patreon API v2 OAuth.
type PatreonOptions struct {
	ClientID     string
	ClientSecret string
	Scopes       []string
	RedirectURI  string
}

// Patreon constructs a ProviderConfig configured for Patreon OAuth authentication.
func Patreon(opts PatreonOptions) *genericoauth.ProviderConfig {
	scopes := opts.Scopes
	if len(scopes) == 0 {
		scopes = []string{"identity", "identity[email]"}
	}

	return &genericoauth.ProviderConfig{
		ProviderID:       "patreon",
		AuthorizationURL: "https://www.patreon.com/oauth2/authorize",
		TokenURL:         "https://www.patreon.com/api/oauth2/token",
		UserInfoURL:      "https://www.patreon.com/api/oauth2/v2/identity",
		ClientID:         opts.ClientID,
		ClientSecret:     opts.ClientSecret,
		Scopes:           scopes,
		RedirectURI:      opts.RedirectURI,
	}
}
