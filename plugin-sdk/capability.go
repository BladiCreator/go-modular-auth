package sdk

import (
	"errors"

	auth "github.com/BladiCreator/go-modular-auth"
)

// Provide registers impl as the strongly typed capability T exposed by the module.
// T is usually an interface exported by the plugin; applications retrieve it with
// auth.Get[T](engine).
func Provide[T any](ctx *Context, impl T) error {
	if ctx == nil || ctx.host == nil {
		return errors.New("plugin-sdk: nil context or host in Provide")
	}
	return auth.Provide[T](ctx.host, impl)
}
