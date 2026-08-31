package entity

import "time"

// Session represents an active authentication session belonging to a user.
type Session struct {
	ID                   string         `json:"id"`
	UserID               string         `json:"userId"`
	Token                string         `json:"token"`
	ExpiresAt            time.Time      `json:"expiresAt"`
	CreatedAt            time.Time      `json:"createdAt"`
	IPAddress            string         `json:"ipAddress,omitempty"`
	UserAgent            string         `json:"userAgent,omitempty"`
	ImpersonatedBy       *string        `json:"impersonatedBy,omitempty"`
	ActiveOrganizationID *string        `json:"activeOrganizationId,omitempty"`
	ActiveTeamID         *string        `json:"activeTeamId,omitempty"`
	DeviceID             *string        `json:"deviceId,omitempty"`
	Extra                map[string]any `json:"extra,omitempty"`
	UpdatedAt            *time.Time     `json:"updatedAt,omitempty"`
}

