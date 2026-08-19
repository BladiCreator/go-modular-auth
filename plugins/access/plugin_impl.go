package access

import (
	"sync"

	"github.com/BladiCreator/go-modular-auth/plugin"
)

// Plugin implements the plugin.Plugin interface for Granular Access Control and RBAC/ABAC in go-modular-auth.
type Plugin struct {
	ac  *AccessControl
	ctx *plugin.Context
	mu  sync.RWMutex
}

// New creates a new Access Control plugin configured with master statements and options.
func New(masterStatements Statements, opts ...Option) *Plugin {
	ac := CreateAccessControl(masterStatements, opts...)
	return &Plugin{
		ac: ac,
	}
}

// NewFromAccessControl creates a Plugin from an existing AccessControl instance.
func NewFromAccessControl(ac *AccessControl) *Plugin {
	return &Plugin{
		ac: ac,
	}
}

// ID returns the unique identifier for the Access Control plugin.
func (p *Plugin) ID() string {
	return "access"
}

// Init initializes the plugin within the shared modular auth context and registers the AccessControl instance.
func (p *Plugin) Init(ctx *plugin.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.ctx = ctx
	ctx.Set(ContextKeyAccessControl, p.ac)
	return nil
}

// AccessControl returns the underlying AccessControl manager instance.
func (p *Plugin) AccessControl() *AccessControl {
	return p.ac
}

// PublishAuthorized emits an EventAccessAuthorized event on the shared EventBus if initialized.
func (p *Plugin) PublishAuthorized(roles []string, req AuthorizeRequest, extra map[string]any) {
	p.mu.RLock()
	ctx := p.ctx
	p.mu.RUnlock()

	if ctx != nil && ctx.Events() != nil {
		ctx.Events().Publish(EventAccessAuthorized, &AccessAuthorizedEventPayload{
			Roles:   roles,
			Request: req,
			Extra:   extra,
		})
	}
}

// PublishDenied emits an EventAccessDenied event on the shared EventBus if initialized.
func (p *Plugin) PublishDenied(roles []string, req AuthorizeRequest, reason string, extra map[string]any) {
	p.mu.RLock()
	ctx := p.ctx
	p.mu.RUnlock()

	if ctx != nil && ctx.Events() != nil {
		ctx.Events().Publish(EventAccessDenied, &AccessDeniedEventPayload{
			Roles:   roles,
			Request: req,
			Reason:  reason,
			Extra:   extra,
		})
	}
}

// PublishRoleCreated emits an EventRoleCreated event on the shared EventBus if initialized.
func (p *Plugin) PublishRoleCreated(role *Role) {
	p.mu.RLock()
	ctx := p.ctx
	p.mu.RUnlock()

	if ctx != nil && ctx.Events() != nil {
		ctx.Events().Publish(EventRoleCreated, &RoleCreatedEventPayload{
			Role: role,
		})
	}
}

// PublishRoleDeleted emits an EventRoleDeleted event on the shared EventBus if initialized.
func (p *Plugin) PublishRoleDeleted(roleName string) {
	p.mu.RLock()
	ctx := p.ctx
	p.mu.RUnlock()

	if ctx != nil && ctx.Events() != nil {
		ctx.Events().Publish(EventRoleDeleted, &RoleDeletedEventPayload{
			RoleName: roleName,
		})
	}
}
