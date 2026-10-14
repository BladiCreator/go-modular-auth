package accountlinking

import (
	"time"

	auth "github.com/BladiCreator/go-modular-auth"
	"github.com/BladiCreator/go-modular-auth/account"
	"github.com/BladiCreator/go-modular-auth/schema"
	"github.com/BladiCreator/go-modular-auth/user"
)

// LinkingTicket holds ephemeral single-use state for two-step account linking ceremonies.
type LinkingTicket struct {
	ID             string            `json:"id"`
	TokenHash      string            `json:"token_hash"`
	UserID         string            `json:"user_id"`
	TargetProvider string            `json:"target_provider,omitempty"`
	Metadata       map[string]string `json:"metadata,omitempty"`
	ConsumedAt     *time.Time        `json:"consumed_at,omitempty"`
	ExpiresAt      time.Time         `json:"expires_at"`
	CreatedAt      time.Time         `json:"created_at"`
}

// Expired reports whether the ticket is expired relative to the given time.
func (t *LinkingTicket) Expired(now time.Time) bool {
	return t != nil && !now.Before(t.ExpiresAt)
}

// IsConsumed reports whether the ticket has already been used.
func (t *LinkingTicket) IsConsumed() bool {
	return t != nil && t.ConsumedAt != nil
}

const (
	ModelLinkingTickets = "linking_tickets"
)

// RegisterSchema registers the linking tickets model in the compiled schema.
func RegisterSchema(s *schema.Schema) error {
	m := schema.NewModel(ModelLinkingTickets, ModelLinkingTickets, "id")
	_ = m.AddField(schema.Field{Name: "id", Type: schema.TypeString, Required: true})
	_ = m.AddField(schema.Field{Name: "token_hash", Type: schema.TypeString, Required: true, Unique: true})
	_ = m.AddField(schema.Field{Name: "user_id", Type: schema.TypeString, Required: true})
	_ = m.AddField(schema.Field{Name: "target_provider", Type: schema.TypeString})
	_ = m.AddField(schema.Field{Name: "metadata", Type: schema.TypeJSON})
	_ = m.AddField(schema.Field{Name: "consumed_at", Type: schema.TypeTime})
	_ = m.AddField(schema.Field{Name: "expires_at", Type: schema.TypeTime, Required: true})
	_ = m.AddField(schema.Field{Name: "created_at", Type: schema.TypeTime, Required: true})
	m.Indexes = []schema.Index{
		{Name: "idx_linking_tickets_hash", Fields: []string{"token_hash"}, Unique: true},
		{Name: "idx_linking_tickets_user", Fields: []string{"user_id"}},
		{Name: "idx_linking_tickets_expires", Fields: []string{"expires_at"}},
	}
	return s.AddModel(m)
}

// Account is an alias to Core Account entity.
type Account = account.Account

// User is an alias to Core User entity.
type User = user.User

// Principal is an alias to Core Principal identity.
type Principal = auth.Principal

// LinkAccountInput specifies the parameters to link a new authentication provider identity to a User.
type LinkAccountInput struct {
	// UserID identifies the canonical Core User.
	UserID string `json:"user_id"`

	// Provider identifies the authentication provider (e.g. "google", "github", "passkey", "password").
	Provider string `json:"provider"`

	// ProviderID identifies the user uniquely inside the provider (e.g. subject, sub, email, or credential ID).
	ProviderID string `json:"provider_id"`

	// Metadata contains optional provider-specific claims or attributes.
	Metadata map[string]string `json:"metadata,omitempty"`
}

// UnlinkAccountInput specifies the parameters to unlink an authentication account by provider name and identifier.
type UnlinkAccountInput struct {
	// UserID identifies the target canonical Core User.
	UserID string `json:"user_id"`

	// Provider identifies the authentication provider to unlink.
	Provider string `json:"provider"`

	// ProviderID identifies the account to unlink within the provider.
	ProviderID string `json:"provider_id"`

	// AllowOrphan overrides the lockout protection, permitting removal of the user's sole remaining auth method.
	AllowOrphan bool `json:"allow_orphan,omitempty"`
}

// UnlinkAccountByIDInput specifies the parameters to unlink an authentication account directly by Core Account ID.
type UnlinkAccountByIDInput struct {
	// UserID identifies the target canonical Core User.
	UserID string `json:"user_id"`

	// AccountID identifies the specific Core Account record to delete.
	AccountID string `json:"account_id"`

	// AllowOrphan overrides the lockout protection, permitting removal of the user's sole remaining auth method.
	AllowOrphan bool `json:"allow_orphan,omitempty"`
}

// CreateTicketInput specifies parameters to initiate a two-step linking ceremony.
type CreateTicketInput struct {
	// UserID identifies the authenticated User initiating the linking flow.
	UserID string `json:"user_id"`

	// TargetProvider restricts the ticket to a specific provider if specified (optional).
	TargetProvider string `json:"target_provider,omitempty"`

	// TTL defines the ticket expiration window. Defaults to plugin configuration if zero.
	TTL time.Duration `json:"ttl,omitempty"`

	// Metadata holds arbitrary state to roundtrip with the ticket (e.g. redirect URI).
	Metadata map[string]string `json:"metadata,omitempty"`
}

// LinkingTicketResult holds the issued ticket metadata and plain token.
type LinkingTicketResult struct {
	// TicketID is the internal identifier.
	TicketID string `json:"ticket_id"`

	// TicketToken is the unhashed bearer token to present when completing the linking ceremony.
	TicketToken string `json:"ticket_token"`

	// UserID is the bound user ID.
	UserID string `json:"user_id"`

	// TargetProvider is the optional restricted provider.
	TargetProvider string `json:"target_provider,omitempty"`

	// ExpiresAt specifies the exact expiration instant.
	ExpiresAt time.Time `json:"expires_at"`
}

// CompleteTicketInput specifies parameters to redeem a linking ticket and attach an external account.
type CompleteTicketInput struct {
	// TicketToken is the unhashed token issued during CreateLinkingTicket.
	TicketToken string `json:"ticket_token"`

	// Provider identifies the authentication provider being linked.
	Provider string `json:"provider"`

	// ProviderID identifies the user within the provider.
	ProviderID string `json:"provider_id"`

	// Metadata contains optional provider claims.
	Metadata map[string]string `json:"metadata,omitempty"`
}
