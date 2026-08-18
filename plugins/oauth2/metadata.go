package oauth2

import (
	"context"
	"fmt"
)

// GetOpenIDConfiguration returns the OpenID Connect Discovery 1.0 metadata document.
func (p *Plugin) GetOpenIDConfiguration(ctx context.Context, params OpenIDConfigurationParams) (*OpenIDConfigurationResult, error) {
	iss := p.config.Issuer

	grants := make([]string, 0, len(p.config.GrantTypes))
	for _, g := range p.config.GrantTypes {
		grants = append(grants, string(g))
	}

	return &OpenIDConfigurationResult{
		Issuer:                            iss,
		AuthorizationEndpoint:             fmt.Sprintf("%s/oauth2/authorize", iss),
		TokenEndpoint:                     fmt.Sprintf("%s/oauth2/token", iss),
		UserinfoEndpoint:                  fmt.Sprintf("%s/oauth2/userinfo", iss),
		IntrospectionEndpoint:             fmt.Sprintf("%s/oauth2/introspect", iss),
		RevocationEndpoint:                fmt.Sprintf("%s/oauth2/revoke", iss),
		EndSessionEndpoint:                fmt.Sprintf("%s/oauth2/logout", iss),
		RegistrationEndpoint:              fmt.Sprintf("%s/oauth2/register", iss),
		JwksURI:                           fmt.Sprintf("%s/oauth2/jwks", iss),
		ResponseTypesSupported:            []string{string(ResponseTypeCode)},
		SubjectTypesSupported:             []string{string(SubjectTypePublic), string(SubjectTypePairwise)},
		IDTokenSigningAlgValuesSupported:  []string{"HS256", "RS256", "EdDSA"},
		ScopesSupported:                   p.config.Scopes,
		TokenEndpointAuthMethodsSupported: []string{string(AuthMethodClientSecretBasic), string(AuthMethodClientSecretPost), string(AuthMethodNone)},
		ClaimsSupported:                   []string{"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce", "at_hash", "c_hash", "name", "email", "email_verified", "phone_number", "phone_number_verified"},
		CodeChallengeMethodsSupported:     []string{CodeChallengeMethodS256},
		GrantTypesSupported:               grants,
	}, nil
}

// GetOAuthAuthorizationServerMetadata returns OAuth 2.0 Authorization Server Metadata per RFC 8414.
func (p *Plugin) GetOAuthAuthorizationServerMetadata(ctx context.Context, params OAuthMetadataParams) (*OAuthMetadataResult, error) {
	iss := p.config.Issuer

	grants := make([]string, 0, len(p.config.GrantTypes))
	for _, g := range p.config.GrantTypes {
		grants = append(grants, string(g))
	}

	return &OAuthMetadataResult{
		Issuer:                            iss,
		AuthorizationEndpoint:             fmt.Sprintf("%s/oauth2/authorize", iss),
		TokenEndpoint:                     fmt.Sprintf("%s/oauth2/token", iss),
		IntrospectionEndpoint:             fmt.Sprintf("%s/oauth2/introspect", iss),
		RevocationEndpoint:                fmt.Sprintf("%s/oauth2/revoke", iss),
		RegistrationEndpoint:              fmt.Sprintf("%s/oauth2/register", iss),
		ResponseTypesSupported:            []string{string(ResponseTypeCode)},
		GrantTypesSupported:               grants,
		CodeChallengeMethodsSupported:     []string{CodeChallengeMethodS256},
		TokenEndpointAuthMethodsSupported: []string{string(AuthMethodClientSecretBasic), string(AuthMethodClientSecretPost), string(AuthMethodNone)},
		ScopesSupported:                   p.config.Scopes,
	}, nil
}
