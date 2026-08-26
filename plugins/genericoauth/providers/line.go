package providers

import (
	"github.com/BladiCreator/go-modular-auth/plugins/genericoauth"
)

// LineOptions defines configuration parameters for Line Login API v2.1.
type LineOptions struct {
	ClientID     string
	ClientSecret string
	Scopes       []string
	RedirectURI  string
}

// Line constructs a ProviderConfig configured for Line Login authentication.
func Line(opts LineOptions) *genericoauth.ProviderConfig {
	scopes := opts.Scopes
	if len(scopes) == 0 {
		scopes = []string{"profile", "openid", "email"}
	}

	return &genericoauth.ProviderConfig{
		ProviderID:       "line",
		AuthorizationURL: "https://access.line.me/oauth2/v2.1/authorize",
		TokenURL:         "https://api.line.me/oauth2/v2.1/token",
		UserInfoURL:      "https://api.line.me/v2/profile",
		ClientID:         opts.ClientID,
		ClientSecret:     opts.ClientSecret,
		Scopes:           scopes,
		RedirectURI:      opts.RedirectURI,
		PKCE:             true,
	}
}
