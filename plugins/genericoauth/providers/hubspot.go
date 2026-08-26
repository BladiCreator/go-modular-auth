package providers

import (
	"github.com/BladiCreator/go-modular-auth/plugins/genericoauth"
)

// HubSpotOptions defines configuration parameters for HubSpot OAuth.
type HubSpotOptions struct {
	ClientID     string
	ClientSecret string
	Scopes       []string
	RedirectURI  string
}

// HubSpot constructs a ProviderConfig configured for HubSpot OAuth authentication.
func HubSpot(opts HubSpotOptions) *genericoauth.ProviderConfig {
	return &genericoauth.ProviderConfig{
		ProviderID:       "hubspot",
		AuthorizationURL: "https://app.hubspot.com/oauth/authorize",
		TokenURL:         "https://api.hubapi.com/oauth/v1/token",
		UserInfoURL:      "https://api.hubapi.com/oauth/v1/access-tokens",
		ClientID:         opts.ClientID,
		ClientSecret:     opts.ClientSecret,
		Scopes:           opts.Scopes,
		RedirectURI:      opts.RedirectURI,
	}
}
