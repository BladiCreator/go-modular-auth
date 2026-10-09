package samlprovider

import "errors"

var (
	ErrSPNotFound       = errors.New("samlprovider: service provider not found")
	ErrInvalidSP        = errors.New("samlprovider: invalid service provider")
	ErrInvalidUser      = errors.New("samlprovider: user is required")
	ErrKeyNotConfigured = errors.New("samlprovider: private key or certificate not configured")
)

// ServiceProvider represents an external SAML SP relying party.
type ServiceProvider struct {
	EntityID    string `json:"entity_id"`
	ACSURL      string `json:"acs_url"`
	Certificate string `json:"certificate,omitempty"`
}
