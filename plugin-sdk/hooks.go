package sdk

import "context"

// HookFunc is a generic synchronous workflow interception function.
type HookFunc[T any] func(ctx context.Context, payload T) error

// HookRegistry provides registration for workflow hooks.
type HookRegistry[T any] struct {
	hooks []HookFunc[T]
}

// NewHookRegistry creates a new hook registry for payload type T.
func NewHookRegistry[T any]() *HookRegistry[T] {
	return &HookRegistry[T]{}
}

// Register appends a hook function to the registry.
func (r *HookRegistry[T]) Register(fn HookFunc[T]) {
	r.hooks = append(r.hooks, fn)
}

// Execute runs all registered hooks sequentially. Aborts on first error.
func (r *HookRegistry[T]) Execute(ctx context.Context, payload T) error {
	for _, fn := range r.hooks {
		if err := fn(ctx, payload); err != nil {
			return err
		}
	}
	return nil
}
