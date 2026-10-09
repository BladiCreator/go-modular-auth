package accountlinking

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"

	auth "github.com/BladiCreator/go-modular-auth"
	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
	"github.com/BladiCreator/go-modular-auth-account-linking/store"
	"github.com/BladiCreator/go-modular-auth/account"
	corestore "github.com/BladiCreator/go-modular-auth/store"
)

type service struct {
	ctx       *sdk.Context
	coreStore corestore.Store
	cfg       Config
}

var _ AccountLinking = (*service)(nil)

func newService(ctx *sdk.Context, cfg Config) *service {
	return &service{
		ctx:       ctx,
		coreStore: ctx.Store(),
		cfg:       cfg,
	}
}

// LinkAccount securely attaches an external provider account to a target User.
func (s *service) LinkAccount(ctx context.Context, in LinkAccountInput) (*account.Account, error) {
	if in.UserID == "" || in.Provider == "" || in.ProviderID == "" {
		return nil, ErrInvalidInput
	}

	actor := s.actorSubject(ctx)
	if err := s.authorizeUserAccess(ctx, in.UserID); err != nil {
		s.emitAudit(ctx, EventLinkFailed, LinkFailedPayload{
			UserID:       in.UserID,
			Provider:     in.Provider,
			ProviderID:   in.ProviderID,
			Reason:       "unauthorized actor",
			ActorSubject: actor,
			Timestamp:    s.cfg.Clock(),
		})
		return nil, err
	}

	return s.linkAccountInternal(ctx, in.UserID, in.Provider, in.ProviderID, actor)
}

func (s *service) linkAccountInternal(ctx context.Context, userID, provider, providerID, actor string) (*account.Account, error) {
	var linkedAccount *account.Account

	err := s.coreStore.Transaction(ctx, func(txCtx context.Context) error {
		// 1. Verify target user exists
		_, err := s.coreStore.Users().GetByID(txCtx, userID)
		if err != nil {
			if errors.Is(err, corestore.ErrNotFound) {
				return ErrUserNotFound
			}
			return err
		}

		// 2. Detect collisions and strictly prevent silent merging
		existing, err := s.coreStore.Accounts().GetByProvider(txCtx, provider, providerID)
		if err == nil && existing != nil {
			if existing.UserID == userID {
				return ErrAccountAlreadyLinked
			}
			// Conflict detected: another user owns this provider account
			s.emitAudit(txCtx, EventLinkFailed, LinkFailedPayload{
				UserID:       userID,
				Provider:     provider,
				ProviderID:   providerID,
				Reason:       fmt.Sprintf("account collision with user %s", existing.UserID),
				ActorSubject: actor,
				Timestamp:    s.cfg.Clock(),
			})
			return ErrAccountConflict
		} else if err != nil && !errors.Is(err, corestore.ErrNotFound) {
			return err
		}

		// 3. Create the Core Account record
		now := s.cfg.Clock()
		newAcc := &account.Account{
			ID:         generateID("acc"),
			UserID:     userID,
			Provider:   provider,
			ProviderID: providerID,
			CreatedAt:  now,
			UpdatedAt:  now,
		}

		if err := s.coreStore.Accounts().Create(txCtx, newAcc); err != nil {
			if errors.Is(err, corestore.ErrConflict) {
				return ErrAccountConflict
			}
			return err
		}

		linkedAccount = newAcc
		return nil
	})

	if err != nil {
		return nil, err
	}

	// 4. Emit success audit event
	s.emitAudit(ctx, EventAccountLinked, AccountLinkedPayload{
		UserID:       userID,
		AccountID:    linkedAccount.ID,
		Provider:     provider,
		ProviderID:   providerID,
		ActorSubject: actor,
		Timestamp:    s.cfg.Clock(),
	})

	return linkedAccount, nil
}

// UnlinkAccount detaches an external provider account from a User by provider and providerID.
func (s *service) UnlinkAccount(ctx context.Context, in UnlinkAccountInput) error {
	if in.UserID == "" || in.Provider == "" || in.ProviderID == "" {
		return ErrInvalidInput
	}

	actor := s.actorSubject(ctx)
	if err := s.authorizeUserAccess(ctx, in.UserID); err != nil {
		s.emitAudit(ctx, EventUnlinkFailed, UnlinkFailedPayload{
			UserID:       in.UserID,
			Provider:     in.Provider,
			ProviderID:   in.ProviderID,
			Reason:       "unauthorized actor",
			ActorSubject: actor,
			Timestamp:    s.cfg.Clock(),
		})
		return err
	}

	var unlinkedID string

	err := s.coreStore.Transaction(ctx, func(txCtx context.Context) error {
		// 1. Locate the account
		acc, err := s.coreStore.Accounts().GetByProvider(txCtx, in.Provider, in.ProviderID)
		if err != nil {
			if errors.Is(err, corestore.ErrNotFound) {
				return ErrAccountNotFound
			}
			return err
		}

		if acc.UserID != in.UserID {
			return ErrAccountNotFound
		}

		// 2. Enforce final usable authentication method protection
		allowOrphan := in.AllowOrphan || s.cfg.AllowOrphanByDefault
		if !allowOrphan {
			canUnlink, err := s.checkRemainingMethods(txCtx, in.UserID, acc.ID)
			if err != nil {
				return err
			}
			if !canUnlink {
				s.emitAudit(txCtx, EventUnlinkFailed, UnlinkFailedPayload{
					UserID:       in.UserID,
					AccountID:    acc.ID,
					Provider:     in.Provider,
					ProviderID:   in.ProviderID,
					Reason:       "attempted to unlink final authentication method",
					ActorSubject: actor,
					Timestamp:    s.cfg.Clock(),
				})
				return ErrCannotUnlinkFinalAuthMethod
			}
		}

		// 3. Delete the account
		if err := s.coreStore.Accounts().Delete(txCtx, acc.ID); err != nil {
			return err
		}

		unlinkedID = acc.ID
		return nil
	})

	if err != nil {
		return err
	}

	s.emitAudit(ctx, EventAccountUnlinked, AccountUnlinkedPayload{
		UserID:       in.UserID,
		AccountID:    unlinkedID,
		Provider:     in.Provider,
		ProviderID:   in.ProviderID,
		ActorSubject: actor,
		Timestamp:    s.cfg.Clock(),
	})

	return nil
}

// UnlinkAccountByID detaches an external provider account from a User by Core Account ID.
func (s *service) UnlinkAccountByID(ctx context.Context, in UnlinkAccountByIDInput) error {
	if in.UserID == "" || in.AccountID == "" {
		return ErrInvalidInput
	}

	actor := s.actorSubject(ctx)
	if err := s.authorizeUserAccess(ctx, in.UserID); err != nil {
		s.emitAudit(ctx, EventUnlinkFailed, UnlinkFailedPayload{
			UserID:       in.UserID,
			AccountID:    in.AccountID,
			Reason:       "unauthorized actor",
			ActorSubject: actor,
			Timestamp:    s.cfg.Clock(),
		})
		return err
	}

	var (
		provider   string
		providerID string
	)

	err := s.coreStore.Transaction(ctx, func(txCtx context.Context) error {
		acc, err := s.coreStore.Accounts().GetByID(txCtx, in.AccountID)
		if err != nil {
			if errors.Is(err, corestore.ErrNotFound) {
				return ErrAccountNotFound
			}
			return err
		}

		if acc.UserID != in.UserID {
			return ErrAccountNotFound
		}

		allowOrphan := in.AllowOrphan || s.cfg.AllowOrphanByDefault
		if !allowOrphan {
			canUnlink, err := s.checkRemainingMethods(txCtx, in.UserID, acc.ID)
			if err != nil {
				return err
			}
			if !canUnlink {
				s.emitAudit(txCtx, EventUnlinkFailed, UnlinkFailedPayload{
					UserID:       in.UserID,
					AccountID:    acc.ID,
					Provider:     acc.Provider,
					ProviderID:   acc.ProviderID,
					Reason:       "attempted to unlink final authentication method",
					ActorSubject: actor,
					Timestamp:    s.cfg.Clock(),
				})
				return ErrCannotUnlinkFinalAuthMethod
			}
		}

		if err := s.coreStore.Accounts().Delete(txCtx, acc.ID); err != nil {
			return err
		}

		provider = acc.Provider
		providerID = acc.ProviderID
		return nil
	})

	if err != nil {
		return err
	}

	s.emitAudit(ctx, EventAccountUnlinked, AccountUnlinkedPayload{
		UserID:       in.UserID,
		AccountID:    in.AccountID,
		Provider:     provider,
		ProviderID:   providerID,
		ActorSubject: actor,
		Timestamp:    s.cfg.Clock(),
	})

	return nil
}

// CreateLinkingTicket issues a single-use ticket for two-step linking ceremonies.
func (s *service) CreateLinkingTicket(ctx context.Context, in CreateTicketInput) (*LinkingTicketResult, error) {
	if in.UserID == "" {
		return nil, ErrInvalidInput
	}

	actor := s.actorSubject(ctx)
	if err := s.authorizeUserAccess(ctx, in.UserID); err != nil {
		return nil, err
	}

	// Verify user exists
	if _, err := s.coreStore.Users().GetByID(ctx, in.UserID); err != nil {
		if errors.Is(err, corestore.ErrNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}

	rawToken, err := generateSecureToken("link_tkt", 32)
	if err != nil {
		return nil, err
	}

	ttl := in.TTL
	if ttl <= 0 {
		ttl = s.cfg.DefaultTicketTTL
	}

	now := s.cfg.Clock()
	expiresAt := now.Add(ttl)
	ticketID := generateID("tkt")

	ticket := &store.LinkingTicket{
		ID:             ticketID,
		TokenHash:      hashToken(rawToken),
		UserID:         in.UserID,
		TargetProvider: in.TargetProvider,
		Metadata:       in.Metadata,
		ExpiresAt:      expiresAt,
		CreatedAt:      now,
	}

	if err := s.cfg.Store.SaveTicket(ctx, ticket); err != nil {
		return nil, err
	}

	s.emitAudit(ctx, EventTicketCreated, TicketCreatedPayload{
		TicketID:       ticketID,
		UserID:         in.UserID,
		TargetProvider: in.TargetProvider,
		ExpiresAt:      expiresAt,
		ActorSubject:   actor,
		Timestamp:      now,
	})

	return &LinkingTicketResult{
		TicketID:       ticketID,
		TicketToken:    rawToken,
		UserID:         in.UserID,
		TargetProvider: in.TargetProvider,
		ExpiresAt:      expiresAt,
	}, nil
}

// CompleteLinkingTicket redeems a linking ticket, validating expiration and single-use redemption.
func (s *service) CompleteLinkingTicket(ctx context.Context, in CompleteTicketInput) (*account.Account, error) {
	if in.TicketToken == "" || in.Provider == "" || in.ProviderID == "" {
		return nil, ErrInvalidInput
	}

	now := s.cfg.Clock()
	tokenHash := hashToken(in.TicketToken)

	// 1. Atomically consume the ticket
	ticket, err := s.cfg.Store.ConsumeTicket(ctx, tokenHash, now)
	if err != nil {
		if errors.Is(err, store.ErrTicketConsumed) {
			return nil, ErrTicketAlreadyUsed
		}
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrTicketNotFound
		}
		return nil, err
	}

	// 2. Validate expiration
	if ticket.Expired(now) {
		return nil, ErrTicketExpired
	}

	// 3. Validate provider restriction if one was specified
	if ticket.TargetProvider != "" && ticket.TargetProvider != in.Provider {
		return nil, ErrProviderMismatch
	}

	// 4. Perform link inside transaction
	return s.linkAccountInternal(ctx, ticket.UserID, in.Provider, in.ProviderID, ticket.UserID)
}

// GetLinkingTicket inspects a linking ticket without consuming it.
func (s *service) GetLinkingTicket(ctx context.Context, ticketToken string) (*LinkingTicket, error) {
	if ticketToken == "" {
		return nil, ErrInvalidInput
	}

	ticket, err := s.cfg.Store.GetTicketByHash(ctx, hashToken(ticketToken))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return nil, ErrTicketNotFound
		}
		return nil, err
	}
	return ticket, nil
}

// RevokeLinkingTicket cancels an active ticket before expiration.
func (s *service) RevokeLinkingTicket(ctx context.Context, ticketToken string) error {
	if ticketToken == "" {
		return ErrInvalidInput
	}

	ticket, err := s.cfg.Store.GetTicketByHash(ctx, hashToken(ticketToken))
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return ErrTicketNotFound
		}
		return err
	}

	return s.cfg.Store.DeleteTicket(ctx, ticket.ID)
}

// ListLinkedAccounts returns all authentication accounts currently attached to a user.
func (s *service) ListLinkedAccounts(ctx context.Context, userID string) ([]*account.Account, error) {
	if userID == "" {
		return nil, ErrInvalidInput
	}
	return s.coreStore.Accounts().ListByUser(ctx, userID)
}

// GetAccount retrieves a specific linked account by provider and provider ID.
func (s *service) GetAccount(ctx context.Context, provider, providerID string) (*account.Account, error) {
	if provider == "" || providerID == "" {
		return nil, ErrInvalidInput
	}
	acc, err := s.coreStore.Accounts().GetByProvider(ctx, provider, providerID)
	if err != nil {
		if errors.Is(err, corestore.ErrNotFound) {
			return nil, ErrAccountNotFound
		}
		return nil, err
	}
	return acc, nil
}

// CanUnlinkAccount evaluates whether the specified account can be safely unlinked.
func (s *service) CanUnlinkAccount(ctx context.Context, userID, accountID string) (bool, error) {
	if userID == "" || accountID == "" {
		return false, ErrInvalidInput
	}
	return s.checkRemainingMethods(ctx, userID, accountID)
}

// checkRemainingMethods verifies that at least one other usable authentication method remains.
func (s *service) checkRemainingMethods(ctx context.Context, userID, accountIDToRemove string) (bool, error) {
	accounts, err := s.coreStore.Accounts().ListByUser(ctx, userID)
	if err != nil {
		return false, err
	}

	remainingAccounts := 0
	for _, a := range accounts {
		if a.ID != accountIDToRemove {
			remainingAccounts++
		}
	}

	if remainingAccounts > 0 {
		return true, nil
	}

	// Check if there are active credentials not tied solely to that account
	creds, err := s.coreStore.Credentials().ListByUser(ctx, userID)
	if err != nil {
		return false, err
	}

	activeCreds := 0
	for _, c := range creds {
		if c.RevokedAt == nil && c.AccountID != accountIDToRemove {
			activeCreds++
		}
	}

	return activeCreds > 0, nil
}

func (s *service) authorizeUserAccess(ctx context.Context, targetUserID string) error {
	p, ok := auth.PrincipalFrom(ctx)
	if !ok {
		// If no Principal in context, allow internal orchestration (e.g. background job, system call)
		return nil
	}

	// Service accounts or identical subjects are authorized
	if p.Subject == targetUserID || p.Type == auth.PrincipalServiceAccount {
		return nil
	}

	return ErrUnauthorized
}

func (s *service) actorSubject(ctx context.Context) string {
	if p, ok := auth.PrincipalFrom(ctx); ok {
		return p.Subject
	}
	return ""
}

func (s *service) emitAudit(ctx context.Context, name auth.EventName, payload any) {
	if s.ctx != nil && s.ctx.Events() != nil {
		s.ctx.Events().Publish(ctx, auth.Event{
			Name:    name,
			Time:    s.cfg.Clock(),
			Payload: payload,
		})
	}
}

func generateID(prefix string) string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return fmt.Sprintf("%s_%s", prefix, hex.EncodeToString(b))
}
