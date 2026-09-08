package stripe

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	// ErrRepositoryRequired is returned when no Repository implementation is provided.
	ErrRepositoryRequired = errors.New("stripe: repository is required")

	// ErrStripeAPIKeyRequired is returned when no Stripe secret API key is configured.
	ErrStripeAPIKeyRequired = errors.New("stripe: stripe API key is required")

	// ErrSubscriptionNotFound is returned when a subscription record cannot be located.
	ErrSubscriptionNotFound = errors.New("stripe: subscription not found")

	// ErrCustomerNotFound is returned when no Stripe Customer ID is linked to an entity.
	ErrCustomerNotFound = errors.New("stripe: customer not found")

	// ErrInvalidWebhookSignature is returned when a Stripe webhook signature fails verification.
	ErrInvalidWebhookSignature = errors.New("stripe: invalid webhook signature")

	// ErrUnauthorizedReference is returned when a user lacks authorization over a referenceId.
	ErrUnauthorizedReference = errors.New("stripe: unauthorized reference access")

	// ErrInvalidPlan is returned when an unrecognized or missing plan ID is specified.
	ErrInvalidPlan = errors.New("stripe: invalid plan specified")
)

// Repository defines the persistent storage contract required by the Stripe plugin.
// Implement this interface on your custom database adapter (e.g. PostgreSQL, MySQL, SQLite, MongoDB, GORM).
//
// # Implementation Example (GORM / database/sql):
//
//	type GormStripeRepository struct {
//		db *gorm.DB
//	}
//
//	func (r *GormStripeRepository) CreateSubscription(ctx context.Context, sub *stripe.Subscription) error {
//		return r.db.WithContext(ctx).Create(sub).Error
//	}
type Repository interface {
	// CreateSubscription persists a new local subscription record linked to Stripe.
	//
	// Function:
	//   Called when a new subscription is provisioned via Checkout or Webhooks.
	//
	// Storage:
	//   Database (GORM / SQL) - Inserts a new row into stripe_subscriptions table.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - sub: Subscription entity to persist.
	//
	// Returns:
	//   - error: Nil on success, or database error on failure.
	//
	// Example SQL:
	//   INSERT INTO stripe_subscriptions (id, plan, reference_id, stripe_customer_id, stripe_subscription_id, status, period_start, period_end, cancel_at_period_end, seats, billing_interval, created_at, updated_at)
	//   VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13);
	CreateSubscription(ctx context.Context, sub *Subscription) error

	// UpdateSubscription updates an existing local subscription record.
	//
	// Function:
	//   Called when subscription status, current period, or seats change via webhook or API.
	//
	// Storage:
	//   Database (GORM / SQL) - Updates fields matching subscription primary key ID.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - sub: Subscription entity with updated fields.
	//
	// Returns:
	//   - error: ErrSubscriptionNotFound if missing, or database error on failure.
	//
	// Example SQL:
	//   UPDATE stripe_subscriptions SET status = $1, period_end = $2, seats = $3, updated_at = NOW() WHERE id = $4;
	UpdateSubscription(ctx context.Context, sub *Subscription) error

	// DeleteSubscription removes a subscription record from storage by local ID.
	//
	// Function:
	//   Called when revoking or permanently deleting a subscription record.
	//
	// Storage:
	//   Database (GORM / SQL) - Deletes row matching local ID.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - id: Local subscription primary key ID.
	//
	// Returns:
	//   - error: ErrSubscriptionNotFound if missing, or database error.
	//
	// Example SQL:
	//   DELETE FROM stripe_subscriptions WHERE id = $1;
	DeleteSubscription(ctx context.Context, id string) error

	// FindSubscriptionByID retrieves a subscription by local primary key ID.
	//
	// Function:
	//   Used in subscription retrieval and cancellation operations.
	//
	// Storage:
	//   Database (GORM / SQL) - Primary key lookup on stripe_subscriptions.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - id: Local subscription primary key ID.
	//
	// Returns:
	//   - *Subscription: Matching subscription record if found.
	//   - error: ErrSubscriptionNotFound if missing, or database error.
	//
	// Example SQL:
	//   SELECT id, plan, reference_id, stripe_customer_id, stripe_subscription_id, status FROM stripe_subscriptions WHERE id = $1 LIMIT 1;
	FindSubscriptionByID(ctx context.Context, id string) (*Subscription, error)

	// FindSubscriptionByStripeID retrieves a subscription by its Stripe-assigned subscription ID.
	//
	// Function:
	//   Used in webhook processing to locate local subscription records matching incoming Stripe events.
	//
	// Storage:
	//   Database (GORM / SQL) - Query by stripe_subscription_id column index.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - stripeSubID: Remote Stripe subscription ID string (e.g. "sub_12345").
	//
	// Returns:
	//   - *Subscription: Matching subscription record if found.
	//   - error: ErrSubscriptionNotFound if missing, or database error.
	//
	// Example SQL:
	//   SELECT id, plan, reference_id, stripe_customer_id, stripe_subscription_id, status FROM stripe_subscriptions WHERE stripe_subscription_id = $1 LIMIT 1;
	FindSubscriptionByStripeID(ctx context.Context, stripeSubID string) (*Subscription, error)

	// ListSubscriptionsByReferenceID retrieves all subscriptions linked to a referenceId (user or organization).
	//
	// Function:
	//   Used by middlewares and service APIs to evaluate active access rights for a user or team.
	//
	// Storage:
	//   Database (GORM / SQL) - Query stripe_subscriptions by reference_id column.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - referenceID: User ID or Organization ID string.
	//
	// Returns:
	//   - []*Subscription: Slice of matching subscription records.
	//   - error: Nil on success, or database error.
	//
	// Example SQL:
	//   SELECT id, plan, reference_id, stripe_customer_id, stripe_subscription_id, status FROM stripe_subscriptions WHERE reference_id = $1;
	ListSubscriptionsByReferenceID(ctx context.Context, referenceID string) ([]*Subscription, error)

	// GetCustomerStripeID retrieves the Stripe Customer ID linked to an entity.
	//
	// Function:
	//   Used during customer billing portal session creation or customer lookup.
	//
	// Storage:
	//   Database (GORM / SQL) - Query stripe_customers by entity_type and entity_id.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - entityType: "user" or "organization".
	//   - entityID: Target user or organization primary key ID.
	//
	// Returns:
	//   - string: Remote Stripe Customer ID (e.g. "cus_12345").
	//   - error: ErrCustomerNotFound if missing, or database error.
	//
	// Example SQL:
	//   SELECT stripe_customer_id FROM stripe_customers WHERE entity_type = $1 AND entity_id = $2 LIMIT 1;
	GetCustomerStripeID(ctx context.Context, entityType, entityID string) (string, error)

	// SaveCustomerStripeID persists the mapping between a local entity and a Stripe Customer ID.
	//
	// Function:
	//   Called after creating a new Customer in Stripe during sign-up or onboarding.
	//
	// Storage:
	//   Database (GORM / SQL) - Upsert row into stripe_customers mapping table.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - entityType: "user" or "organization".
	//   - entityID: Local entity ID string.
	//   - stripeCustomerID: Remote Stripe Customer ID string.
	//
	// Returns:
	//   - error: Nil on success, or database error.
	//
	// Example SQL:
	//   INSERT INTO stripe_customers (entity_type, entity_id, stripe_customer_id, created_at) VALUES ($1, $2, $3, NOW())
	//   ON CONFLICT (entity_type, entity_id) DO UPDATE SET stripe_customer_id = EXCLUDED.stripe_customer_id;
	SaveCustomerStripeID(ctx context.Context, entityType, entityID, stripeCustomerID string) error
}

// MemoryRepository provides a thread-safe, in-memory implementation of Repository for testing and lightweight usage.
type MemoryRepository struct {
	mu            sync.RWMutex
	subscriptions map[string]*Subscription // keyed by ID
	stripeSubMap  map[string]string        // stripeSubID -> subID
	customers     map[string]string        // "entityType:entityID" -> stripeCustomerID
}

// NewMemoryRepository initializes a fresh MemoryRepository instance.
func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{
		subscriptions: make(map[string]*Subscription),
		stripeSubMap:  make(map[string]string),
		customers:     make(map[string]string),
	}
}

// CreateSubscription persists a new subscription entity in memory.
func (r *MemoryRepository) CreateSubscription(_ context.Context, sub *Subscription) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if sub.ID == "" {
		sub.ID = fmt.Sprintf("sub_loc_%d", time.Now().UnixNano())
	}
	now := time.Now()
	if sub.CreatedAt.IsZero() {
		sub.CreatedAt = now
	}
	sub.UpdatedAt = now

	cp := *sub
	r.subscriptions[sub.ID] = &cp
	if sub.StripeSubscriptionID != "" {
		r.stripeSubMap[sub.StripeSubscriptionID] = sub.ID
	}
	return nil
}

// UpdateSubscription updates an existing in-memory subscription entity.
func (r *MemoryRepository) UpdateSubscription(_ context.Context, sub *Subscription) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	existing, ok := r.subscriptions[sub.ID]
	if !ok {
		return ErrSubscriptionNotFound
	}

	sub.UpdatedAt = time.Now()
	if sub.CreatedAt.IsZero() {
		sub.CreatedAt = existing.CreatedAt
	}

	cp := *sub
	r.subscriptions[sub.ID] = &cp
	if sub.StripeSubscriptionID != "" {
		r.stripeSubMap[sub.StripeSubscriptionID] = sub.ID
	}
	return nil
}

// DeleteSubscription removes an in-memory subscription entity by ID.
func (r *MemoryRepository) DeleteSubscription(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	sub, ok := r.subscriptions[id]
	if !ok {
		return ErrSubscriptionNotFound
	}

	delete(r.subscriptions, id)
	if sub.StripeSubscriptionID != "" {
		delete(r.stripeSubMap, sub.StripeSubscriptionID)
	}
	return nil
}

// FindSubscriptionByID retrieves an in-memory subscription by local ID.
func (r *MemoryRepository) FindSubscriptionByID(_ context.Context, id string) (*Subscription, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	sub, ok := r.subscriptions[id]
	if !ok {
		return nil, ErrSubscriptionNotFound
	}
	cp := *sub
	return &cp, nil
}

// FindSubscriptionByStripeID retrieves an in-memory subscription by remote Stripe ID.
func (r *MemoryRepository) FindSubscriptionByStripeID(_ context.Context, stripeSubID string) (*Subscription, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	id, ok := r.stripeSubMap[stripeSubID]
	if !ok {
		return nil, ErrSubscriptionNotFound
	}
	sub, ok := r.subscriptions[id]
	if !ok {
		return nil, ErrSubscriptionNotFound
	}
	cp := *sub
	return &cp, nil
}

// ListSubscriptionsByReferenceID retrieves all in-memory subscriptions linked to a referenceId.
func (r *MemoryRepository) ListSubscriptionsByReferenceID(_ context.Context, referenceID string) ([]*Subscription, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result []*Subscription
	for _, sub := range r.subscriptions {
		if sub.ReferenceID == referenceID {
			cp := *sub
			result = append(result, &cp)
		}
	}
	return result, nil
}

// GetCustomerStripeID retrieves the Stripe Customer ID linked to an entity in memory.
func (r *MemoryRepository) GetCustomerStripeID(_ context.Context, entityType, entityID string) (string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	key := fmt.Sprintf("%s:%s", entityType, entityID)
	custID, ok := r.customers[key]
	if !ok || custID == "" {
		return "", ErrCustomerNotFound
	}
	return custID, nil
}

// SaveCustomerStripeID persists the entity-to-Stripe Customer ID mapping in memory.
func (r *MemoryRepository) SaveCustomerStripeID(_ context.Context, entityType, entityID, stripeCustomerID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := fmt.Sprintf("%s:%s", entityType, entityID)
	r.customers[key] = stripeCustomerID
	return nil
}
