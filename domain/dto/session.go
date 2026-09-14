package dto

import (
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
)

type (
	// CreateSessionParams defines full session parameters passed to repository implementations with dynamic extra metadata.
	CreateSessionParams struct {
		UserID               string         `json:"user_id" binding:"required"`
		DeviceID             string         `json:"device_id,omitzero"`
		Token                string         `json:"token" binding:"required"`
		IPAddress            string         `json:"ip_address,omitzero"`
		UserAgent            string         `json:"user_agent,omitzero"`
		ImpersonatedBy       *string        `json:"impersonated_by,omitzero"`
		ActiveOrganizationID *string        `json:"active_organization_id,omitzero"`
		ActiveTeamID         *string        `json:"active_team_id,omitzero"`
		ExpiresAt            time.Time      `json:"expires_at" binding:"required"`
		CreatedAt            time.Time      `json:"created_at" binding:"required"`
		Extra                map[string]any `json:"extra,omitzero"`
	}

	// UpdateSessionParams defines mutable fields when updating an active session.
	UpdateSessionParams struct {
		ID                   string         `json:"id" binding:"required"`
		IPAddress            *string        `json:"ip_address,omitzero"`
		UserAgent            *string        `json:"user_agent,omitzero"`
		ActiveOrganizationID *string        `json:"active_organization_id,omitzero"`
		ActiveTeamID         *string        `json:"active_team_id,omitzero"`
		ExpiresAt            *time.Time     `json:"expires_at,omitzero"`
		UpdatedAt            *time.Time     `json:"updated_at,omitzero"`
		Extra                map[string]any `json:"extra,omitzero"`
	}

	// SessionFilter defines criteria for searching and paginating user sessions.
	SessionFilter struct {
		UserID               string `json:"user_id,omitzero"`
		ActiveOrganizationID string `json:"active_organization_id,omitzero"`
		Limit                int    `json:"limit,omitzero"`
		Offset               int    `json:"offset,omitzero"`
	}

	// SessionData holds the combined session and user information returned by session endpoints.
	SessionData struct {
		Session *entity.Session `json:"session"`
		User    *entity.User    `json:"user"`
	}
)
