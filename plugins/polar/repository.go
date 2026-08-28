package polar

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	// ErrRepositoryRequired is returned when no Repository implementation is provided.
	ErrRepositoryRequired = errors.New("polar: repository is required")

	// ErrAccessTokenRequired is returned when no Polar Bearer access token is configured.
	ErrAccessTokenRequired = errors.New("polar: access token is required")

	// ErrSubscriptionNotFound is returned when a subscription record cannot be located.
	ErrSubscriptionNotFound = errors.New("polar: subscription not found")

	// ErrCustomerNotFound is returned when no Polar Customer ID is linked to an entity.
	ErrCustomerNotFound = errors.New("polar: customer not found")

	// ErrInvalidWebhookSignature is returned when a Polar webhook signature fails verification.
	ErrInvalidWebhookSignature = errors.New("polar: invalid webhook signature")

	// ErrUnauthorizedReference is returned when a user lacks authorization over a referenceId.
	ErrUnauthorizedReference = errors.New("polar: unauthorized reference access")

	// ErrInvalidPlan is returned when an unrecognized or missing plan ID is specified.
	ErrInvalidPlan = errors.New("polar: invalid plan specified")
)

// Repository defines the persistent storage contract required by the Polar plugin.
// Implement this interface on your custom database adapter (e.g. PostgreSQL, MySQL, SQLite, MongoDB, GORM).
//
// # Implementation Example (GORM / database/sql):
//
//	type GormPolarRepository struct {
//		db *gorm.DB
//	}
//
//	func (r *GormPolarRepository) CreateSubscription(ctx context.Context, sub *polar.Subscription) error {
//		return r.db.WithContext(ctx).Create(sub).Error
//	}
type Repository interface {
	// CreateSubscription persists a new local subscription record linked to Polar.
	//
	// Function:
	//   Called when a new subscription is provisioned via Checkout or Webhooks.
	//
	// Storage:
	//   Database (GORM / SQL) - Inserts a new row into polar_subscriptions table.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - sub: Subscription entity to persist.
	//
	// Returns:
	//   - error: Nil on success, or database error on failure.
	//
	// Example SQL:
	//   INSERT INTO polar_subscriptions (id, plan_id, reference_id, polar_customer_id, polar_subscription_id, status, period_start, period_end, cancel_at_period_end, seats, created_at, updated_at)
	//   VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12);
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
	//   UPDATE polar_subscriptions SET status = $1, period_end = $2, seats = $3, updated_at = NOW() WHERE id = $4;
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
	//   DELETE FROM polar_subscriptions WHERE id = $1;
	DeleteSubscription(ctx context.Context, id string) error

	// FindSubscriptionByID retrieves a subscription by local primary key ID.
	//
	// Function:
	//   Used in subscription retrieval and cancellation operations.
	//
	// Storage:
	//   Database (GORM / SQL) - Primary key lookup on polar_subscriptions.
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
	//   SELECT id, plan_id, reference_id, polar_customer_id, polar_subscription_id, status FROM polar_subscriptions WHERE id = $1 LIMIT 1;
	FindSubscriptionByID(ctx context.Context, id string) (*Subscription, error)

	// FindSubscriptionByPolarID retrieves a subscription by its Polar-assigned subscription ID.
	//
	// Function:
	//   Used in webhook processing to locate local subscription records matching incoming Polar events.
	//
	// Storage:
	//   Database (GORM / SQL) - Query by polar_subscription_id column index.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - polarSubID: Remote Polar subscription ID string.
	//
	// Returns:
	//   - *Subscription: Matching subscription record if found.
	//   - error: ErrSubscriptionNotFound if missing, or database error.
	//
	// Example SQL:
	//   SELECT id, plan_id, reference_id, polar_customer_id, polar_subscription_id, status FROM polar_subscriptions WHERE polar_subscription_id = $1 LIMIT 1;
	FindSubscriptionByPolarID(ctx context.Context, polarSubID string) (*Subscription, error)

	// ListSubscriptionsByReferenceID retrieves all subscriptions linked to a referenceId (user or organization).
	//
	// Function:
	//   Used by middlewares and service APIs to evaluate active access rights for a user or team.
	//
	// Storage:
	//   Database (GORM / SQL) - Query polar_subscriptions by reference_id column.
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
	//   SELECT id, plan_id, reference_id, polar_customer_id, polar_subscription_id, status FROM polar_subscriptions WHERE reference_id = $1;
	ListSubscriptionsByReferenceID(ctx context.Context, referenceID string) ([]*Subscription, error)

	// GetCustomerPolarID retrieves the Polar Customer ID linked to an entity.
	//
	// Function:
	//   Used during customer portal session creation or usage event ingestion.
	//
	// Storage:
	//   Database (GORM / SQL) - Query polar_customers by entity_type and entity_id.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - entityType: "user" or "organization".
	//   - entityID: Target user or organization primary key ID.
	//
	// Returns:
	//   - string: Remote Polar Customer ID.
	//   - error: ErrCustomerNotFound if missing, or database error.
	//
	// Example SQL:
	//   SELECT polar_customer_id FROM polar_customers WHERE entity_type = $1 AND entity_id = $2 LIMIT 1;
	GetCustomerPolarID(ctx context.Context, entityType, entityID string) (string, error)

	// SaveCustomerPolarID persists the mapping between a local entity and a Polar Customer ID.
	//
	// Function:
	//   Called after creating a new Customer in Polar during sign-up or onboarding.
	//
	// Storage:
	//   Database (GORM / SQL) - Upsert row into polar_customers mapping table.
	//
	// Arguments:
	//   - ctx: Request cancellation context.
	//   - entityType: "user" or "organization".
	//   - entityID: Local entity ID string.
	//   - polarCustomerID: Remote Polar Customer ID string.
	//
	// Returns:
	//   - error: Nil on success, or database error.
	//
	// Example SQL:
	//   INSERT INTO polar_customers (entity_type, entity_id, polar_customer_id, created_at) VALUES ($1, $2, $3, NOW())
	//   ON CONFLICT (entity_type, entity_id) DO UPDATE SET polar_customer_id = EXCLUDED.polar_customer_id;
	SaveCustomerPolarID(ctx context.Context, entityType, entityID, polarCustomerID string) error
}

// MemoryRepository provides a thread-safe, in-memory implementation of Repository for testing and lightweight usage.
type MemoryRepository struct {
	mu            sync.RWMutex
	subscriptions map[string]*Subscription // keyed by local ID
	polarSubMap   map[string]string        // polarSubID -> subID
	customers     map[string]string        // "entityType:entityID" -> polarCustomerID
}

// NewMemoryRepository initializes a fresh MemoryRepository instance.
func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{
		subscriptions: make(map[string]*Subscription),
		polarSubMap:   make(map[string]string),
		customers:     make(map[string]string),
	}
}

// CreateSubscription persists a new subscription entity in memory.
func (r *MemoryRepository) CreateSubscription(_ context.Context, sub *Subscription) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if sub.ID == "" {
		sub.ID = fmt.Sprintf("pol_sub_loc_%d", time.Now().UnixNano())
	}
	now := time.Now()
	if sub.CreatedAt.IsZero() {
		sub.CreatedAt = now
	}
	sub.UpdatedAt = now

	cp := *sub
	r.subscriptions[sub.ID] = &cp
	if sub.PolarSubscriptionID != "" {
		r.polarSubMap[sub.PolarSubscriptionID] = sub.ID
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
	if sub.PolarSubscriptionID != "" {
		r.polarSubMap[sub.PolarSubscriptionID] = sub.ID
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
	if sub.PolarSubscriptionID != "" {
		delete(r.polarSubMap, sub.PolarSubscriptionID)
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

// FindSubscriptionByPolarID retrieves an in-memory subscription by remote Polar ID.
func (r *MemoryRepository) FindSubscriptionByPolarID(_ context.Context, polarSubID string) (*Subscription, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	id, ok := r.polarSubMap[polarSubID]
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

// GetCustomerPolarID retrieves the Polar Customer ID linked to an entity in memory.
func (r *MemoryRepository) GetCustomerPolarID(_ context.Context, entityType, entityID string) (string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	key := fmt.Sprintf("%s:%s", entityType, entityID)
	custID, ok := r.customers[key]
	if !ok || custID == "" {
		return "", ErrCustomerNotFound
	}
	return custID, nil
}

// SaveCustomerPolarID persists the entity-to-Polar Customer ID mapping in memory.
func (r *MemoryRepository) SaveCustomerPolarID(_ context.Context, entityType, entityID, polarCustomerID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := fmt.Sprintf("%s:%s", entityType, entityID)
	r.customers[key] = polarCustomerID
	return nil
}
