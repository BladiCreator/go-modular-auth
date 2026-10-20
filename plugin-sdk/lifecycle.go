package sdk

import (
	auth "github.com/BladiCreator/go-modular-auth"
)

// Lifecycle defines optional lifecycle callbacks that a plugin module can implement.
// It is an alias to auth.Lifecycle for seamless backward compatibility.
type Lifecycle = auth.Lifecycle
