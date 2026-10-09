package scim

import "github.com/BladiCreator/go-modular-auth-scim/store"

type Config struct {
	Store store.Store
}

type Option func(*Config)

func WithStore(st store.Store) Option {
	return func(c *Config) {
		c.Store = st
	}
}
