package admin

// Standard role constants.
const (
	RoleAdmin = "admin"
	RoleUser  = "user"
)

// Standard access control resources.
const (
	ResourceUser    = "user"
	ResourceSession = "session"
)

// Standard actions for the 'user' resource.
const (
	ActionCreate            = "create"
	ActionList              = "list"
	ActionGet               = "get"
	ActionUpdate            = "update"
	ActionDelete            = "delete"
	ActionSetRole           = "set-role"
	ActionBan               = "ban"
	ActionImpersonate       = "impersonate"
	ActionImpersonateAdmins = "impersonate-admins"
	ActionSetPassword       = "set-password"
	ActionSetEmail          = "set-email"
)

// Standard actions for the 'session' resource.
const (
	ActionSessionList   = "list"
	ActionSessionRevoke = "revoke"
	ActionSessionDelete = "delete"
)

// Standard metadata and context keys for Extra payloads and shared plugin.Context storage.
const (
	ExtraKeyImpersonatedBy = "impersonated_by"
	ExtraKeyAdminSession   = "admin_session"
	ExtraKeyBanReason      = "ban_reason"
	ExtraKeyBanExpires     = "ban_expires"
	ExtraKeyRole           = "role"
)
