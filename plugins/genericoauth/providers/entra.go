package providers

import (
	"fmt"

	"github.com/BladiCreator/go-modular-auth/plugins/genericoauth"
)

// EntraOptions defines configuration parameters for Microsoft Entra ID (Azure AD).
type EntraOptions struct {
	TenantID     string
	ClientID     string
	ClientSecret string
	Scopes       []string
	RedirectURI  string
	PKCE         bool
}

// Entra constructs a ProviderConfig configured for Microsoft Entra ID.
func Entra(opts EntraOptions) *genericoauth.ProviderConfig {
	tenantID := opts.TenantID
	if tenantID == "" {
		tenantID = "common"
	}

	discoveryURL := fmt.Sprintf("https://login.microsoftonline.com/%s/v2.0/.well-known/openid-configuration", tenantID)

	scopes := opts.Scopes
	if len(scopes) == 0 {
		scopes = []string{"openid", "profile", "email", "User.Read"}
	}

	return &genericoauth.ProviderConfig{
		ProviderID:   "entra-id",
		DiscoveryURL: discoveryURL,
		ClientID:     opts.ClientID,
		ClientSecret: opts.ClientSecret,
		Scopes:       scopes,
		RedirectURI:  opts.RedirectURI,
		PKCE:         opts.PKCE,
	}
}
