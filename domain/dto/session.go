package dto

import "time"

type (
	// CreateSessionParams defines full session parameters passed to repository implementations with dynamic extra metadata.
	CreateSessionParams struct {
		UserID    string         `json:"user_id" binding:"required"`
		DeviceID  string         `json:"device_id"`
		Token     string         `json:"token" binding:"required"`
		IPAddress string         `json:"ip_address"`
		UserAgent string         `json:"user_agent"`
		ExpiresAt time.Time      `json:"expires_at" binding:"required"`
		CreatedAt time.Time      `json:"created_at" binding:"required"`
		Extra     map[string]any `json:"extra,omitempty"`
	}
)

// Set allows plugins or handlers to safely attach dynamic metadata.
func (p *CreateSessionParams) Set(key string, value any) {
	if p.Extra == nil {
		p.Extra = make(map[string]any)
	}
	p.Extra[key] = value
}

// Get safely retrieves dynamic metadata by key.
func (p *CreateSessionParams) Get(key string) (any, bool) {
	if p.Extra == nil {
		return nil, false
	}
	val, ok := p.Extra[key]
	return val, ok
}
