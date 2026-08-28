package dto

import (
	"time"

	"github.com/BladiCreator/go-modular-auth/domain/entity"
	"github.com/BladiCreator/go-modular-auth/plugin"
)

type (
	// CreateSessionParams defines full session parameters passed to repository implementations with dynamic extra metadata.
	CreateSessionParams struct {
		UserID         string    `json:"user_id" binding:"required"`
		DeviceID       string    `json:"device_id"`
		Token          string    `json:"token" binding:"required"`
		IPAddress      string    `json:"ip_address"`
		UserAgent      string    `json:"user_agent"`
		ImpersonatedBy *string   `json:"impersonated_by,omitempty"`
		ExpiresAt      time.Time `json:"expires_at" binding:"required"`
		CreatedAt      time.Time `json:"created_at" binding:"required"`
		plugin.ExtraContainer
	}
	// SessionData holds the combined session and user information returned by session endpoints.
	SessionData struct {
		Session *entity.Session `json:"session"`
		User    *entity.User    `json:"user"`
		plugin.ExtraContainer
	}
)
