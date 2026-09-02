package dto

import (
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
)

type (
	// CreateSessionParams defines full session parameters passed to repository implementations with dynamic extra metadata.
	CreateSessionParams struct {
		UserID               string    `json:"user_id" binding:"required"`
		DeviceID             string    `json:"device_id,omitempty"`
		Token                string    `json:"token" binding:"required"`
		IPAddress            string    `json:"ip_address,omitempty"`
		UserAgent            string    `json:"user_agent,omitempty"`
		ImpersonatedBy       *string   `json:"impersonated_by,omitempty"`
		ActiveOrganizationID *string   `json:"active_organization_id,omitempty"`
		ActiveTeamID         *string   `json:"active_team_id,omitempty"`
		ExpiresAt            time.Time `json:"expires_at" binding:"required"`
		CreatedAt            time.Time `json:"created_at" binding:"required"`
		entity.ExtraContainer
	}

	// UpdateSessionParams defines mutable fields when updating an active session.
	UpdateSessionParams struct {
		ID                   string     `json:"id" binding:"required"`
		IPAddress            *string    `json:"ip_address,omitempty"`
		UserAgent            *string    `json:"user_agent,omitempty"`
		ActiveOrganizationID *string    `json:"active_organization_id,omitempty"`
		ActiveTeamID         *string    `json:"active_team_id,omitempty"`
		ExpiresAt            *time.Time `json:"expires_at,omitempty"`
		UpdatedAt            *time.Time `json:"updated_at,omitempty"`
		entity.ExtraContainer
	}

	// SessionFilter defines criteria for searching and paginating user sessions.
	SessionFilter struct {
		UserID               string `json:"user_id,omitempty"`
		ActiveOrganizationID string `json:"active_organization_id,omitempty"`
		Limit                int    `json:"limit,omitempty"`
		Offset               int    `json:"offset,omitempty"`
	}

	// SessionData holds the combined session and user information returned by session endpoints.
	SessionData struct {
		Session *entity.Session `json:"session"`
		User    *entity.User    `json:"user"`
		entity.ExtraContainer
	}
)

