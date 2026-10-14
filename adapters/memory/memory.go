// Package memory provides in-memory implementations of GoModularAuth infrastructure adapters:
// Store, Cache, and Email.
//
// These adapters are intended for unit tests, development, and standalone testing
// of plugins without requiring external database or cache services.
package memory

import (
	"github.com/BladiCreator/go-modular-auth/adapter"
	adaptermem "github.com/BladiCreator/go-modular-auth/adapter/memory"
	"github.com/BladiCreator/go-modular-auth/cache"
	cachemem "github.com/BladiCreator/go-modular-auth/cache/memory"
	"github.com/BladiCreator/go-modular-auth/email"
	emailmem "github.com/BladiCreator/go-modular-auth/email/memory"
)

// NewAdapter creates a thread-safe in-memory generic database Adapter satisfying adapter.Adapter.
func NewAdapter() adapter.Adapter {
	return adaptermem.New()
}

// NewCache creates an in-memory Cache adapter satisfying cache.Cache.
func NewCache() cache.Cache {
	return cachemem.New()
}

// NewEmail creates an in-memory transactional email sender satisfying email.Sender.
func NewEmail() email.Sender {
	return emailmem.New()
}
