// Package events exports administrative audit event types for GoModularAuth.
package events

import (
	"github.com/BladiCreator/go-modular-auth/plugins/admin"
)

const (
	EventUserDisabled           = admin.EventUserDisabled
	EventUserEnabled            = admin.EventUserEnabled
	EventUserDeleted            = admin.EventUserDeleted
	EventSessionRevoked         = admin.EventSessionRevoked
	EventPasswordResetInitiated = admin.EventPasswordResetInitiated
	EventEmailVerified          = admin.EventEmailVerified
	EventAdminRoleAssigned      = admin.EventAdminRoleAssigned
)

type UserDisabledPayload = admin.UserDisabledPayload
type UserEnabledPayload = admin.UserEnabledPayload
type UserDeletedPayload = admin.UserDeletedPayload
type SessionRevokedPayload = admin.SessionRevokedPayload
type PasswordResetInitiatedPayload = admin.PasswordResetInitiatedPayload
type EmailVerifiedPayload = admin.EmailVerifiedPayload
type AdminRoleAssignedPayload = admin.AdminRoleAssignedPayload
