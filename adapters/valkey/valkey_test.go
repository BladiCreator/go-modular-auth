package valkey_test

import (
	"testing"

	"github.com/BladiCreator/go-modular-auth/adapters/valkey"
	"github.com/BladiCreator/go-modular-auth/cache"
)

func TestInterfaceCompliance(t *testing.T) {
	var _ cache.Cache = (*valkey.Cache)(nil)
	var _ cache.Counter = (*valkey.Cache)(nil)
}
