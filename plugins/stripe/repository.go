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

// Repository defines the storage contract for persisting and querying Stripe subscriptions and customer mappings.
type Repository interface {
	CreateSubscription(ctx context.Context, sub *Subscription) error
	UpdateSubscription(ctx context.Context, sub *Subscription) error
	DeleteSubscription(ctx context.Context, id string) error
	FindSubscriptionByID(ctx context.Context, id string) (*Subscription, error)
	FindSubscriptionByStripeID(ctx context.Context, stripeSubID string) (*Subscription, error)
	ListSubscriptionsByReferenceID(ctx context.Context, referenceID string) ([]*Subscription, error)
	GetCustomerStripeID(ctx context.Context, entityType, entityID string) (string, error)
	SaveCustomerStripeID(ctx context.Context, entityType, entityID, stripeCustomerID string) error
}

// MemoryRepository provides a thread-safe, in-memory implementation of Repository for testing and lightweight usage.
type MemoryRepository struct {
	mu            sync.RWMutex
	subscriptions map[string]*Subscription       // keyed by ID
	stripeSubMap  map[string]string              // stripeSubID -> subID
	customers     map[string]string              // "entityType:entityID" -> stripeCustomerID
}

// NewMemoryRepository initializes a fresh MemoryRepository instance.
func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{
		subscriptions: make(map[string]*Subscription),
		stripeSubMap:  make(map[string]string),
		customers:     make(map[string]string),
	}
}

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

func (r *MemoryRepository) SaveCustomerStripeID(_ context.Context, entityType, entityID, stripeCustomerID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	key := fmt.Sprintf("%s:%s", entityType, entityID)
	r.customers[key] = stripeCustomerID
	return nil
}
