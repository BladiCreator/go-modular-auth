package providers

import (
	"github.com/BladiCreator/go-modular-auth/plugins/genericoauth"
)

// SlackOptions defines configuration parameters for Slack OAuth v2.
type SlackOptions struct {
	ClientID     string
	ClientSecret string
	Scopes       []string
	RedirectURI  string
}

// Slack constructs a ProviderConfig configured for Slack authentication.
func Slack(opts SlackOptions) *genericoauth.ProviderConfig {
	scopes := opts.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email"}
	}

	return &genericoauth.ProviderConfig{
		ProviderID:       "slack",
		AuthorizationURL: "https://slack.com/openid/connect/authorize",
		TokenURL:         "https://slack.com/api/openid.connect.token",
		UserInfoURL:      "https://slack.com/api/openid.connect.userInfo",
		ClientID:         opts.ClientID,
		ClientSecret:     opts.ClientSecret,
		Scopes:           scopes,
		RedirectURI:      opts.RedirectURI,
		PKCE:             true,
	}
}
