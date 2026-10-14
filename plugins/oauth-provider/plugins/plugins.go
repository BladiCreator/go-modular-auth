// Package plugins exposes capability aliases for GoModularAuth plugins.
package plugins

import (
	oauthprovider "github.com/BladiCreator/go-modular-auth/plugins/oauth-provider"
)

// OAuthProvider is the strongly typed capability provided by the oauth-provider module.
type OAuthProvider = oauthprovider.OAuthProvider
