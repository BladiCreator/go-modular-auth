package accountlinking

import (
	"context"

	"github.com/BladiCreator/go-modular-auth/account"
)

// AccountLinking defines the strongly typed capability for orchestrating secure
// account linking and unlinking across any authentication mechanism in GoModularAuth.
//
// Applications and transport adapters retrieve this capability via:
//
//	linking, err := auth.Get[plugins.AccountLinking](engine)
//	// or
//	linking, err := auth.Get[accountlinking.AccountLinking](engine)
type AccountLinking interface {
	// LinkAccount securely attaches an external provider account to a target User.
	// It participates in a Store transaction, enforces caller authorization, prevents
	// silent merging across distinct users (detecting collisions), and emits audit events.
	LinkAccount(ctx context.Context, in LinkAccountInput) (*account.Account, error)

	// UnlinkAccount detaches an external provider account from a User by provider and providerID.
	// Fails with ErrCannotUnlinkFinalAuthMethod if this is the user's sole authentication method
	// unless AllowOrphan is explicitly enabled.
	UnlinkAccount(ctx context.Context, in UnlinkAccountInput) error

	// UnlinkAccountByID detaches an external provider account from a User by Core Account ID.
	// Enforces ownership and final authentication method protection.
	UnlinkAccountByID(ctx context.Context, in UnlinkAccountByIDInput) error

	// CreateLinkingTicket issues a single-use, time-limited, cryptographically random ticket
	// for two-step linking flows (e.g. initiating linking in session, completing after OAuth/WebAuthn redirect).
	CreateLinkingTicket(ctx context.Context, in CreateTicketInput) (*LinkingTicketResult, error)

	// CompleteLinkingTicket redeems a linking ticket, validating expiration, single-use redemption,
	// and provider restrictions, before linking the account within a Store transaction.
	CompleteLinkingTicket(ctx context.Context, in CompleteTicketInput) (*account.Account, error)

	// GetLinkingTicket inspects a linking ticket by its plain token without consuming it.
	GetLinkingTicket(ctx context.Context, ticketToken string) (*LinkingTicket, error)

	// RevokeLinkingTicket cancels an active linking ticket before expiration.
	RevokeLinkingTicket(ctx context.Context, ticketToken string) error

	// ListLinkedAccounts returns all authentication accounts currently attached to a user.
	ListLinkedAccounts(ctx context.Context, userID string) ([]*account.Account, error)

	// GetAccount retrieves a specific linked account by provider and provider ID.
	GetAccount(ctx context.Context, provider, providerID string) (*account.Account, error)

	// CanUnlinkAccount evaluates whether the specified account can be safely unlinked
	// without leaving the user without any authentication methods.
	CanUnlinkAccount(ctx context.Context, userID, accountID string) (bool, error)
}
