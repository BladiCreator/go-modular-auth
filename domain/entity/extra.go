package entity

// ExtraContainer provides a reusable map for dynamic metadata with Set and Get methods.
// Embed entity.ExtraContainer in domain entities, DTOs, and session options.
type ExtraContainer struct {
	// Extra holds dynamic metadata passed through event interceptors or custom extensions.
	Extra map[string]any `json:"extra,omitempty"`
}

// Set stores a key-value pair in the Extra metadata map.
func (e *ExtraContainer) Set(key string, val any) {
	if e.Extra == nil {
		e.Extra = make(map[string]any)
	}
	e.Extra[key] = val
}

// Get retrieves a value from the Extra metadata map by key.
func (e *ExtraContainer) Get(key string) (any, bool) {
	if e.Extra == nil {
		return nil, false
	}
	v, ok := e.Extra[key]
	return v, ok
}
