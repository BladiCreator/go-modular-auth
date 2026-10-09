package organizations

import (
	"context"

	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
)

// Hooks provides custom interceptor hooks for organization workflows.
type Hooks struct {
	beforeOrgCreate *sdk.HookRegistry[*CreateOrganizationInput]
	afterOrgCreate  *sdk.HookRegistry[*OrganizationRecord]
	beforeMemberAdd *sdk.HookRegistry[*AddMemberInput]
	afterMemberAdd  *sdk.HookRegistry[*Membership]
}

// NewHooks creates a new Hooks container.
func NewHooks() *Hooks {
	return &Hooks{
		beforeOrgCreate: sdk.NewHookRegistry[*CreateOrganizationInput](),
		afterOrgCreate:  sdk.NewHookRegistry[*OrganizationRecord](),
		beforeMemberAdd: sdk.NewHookRegistry[*AddMemberInput](),
		afterMemberAdd:  sdk.NewHookRegistry[*Membership](),
	}
}

// BeforeOrganizationCreate registers a hook executed prior to organization persistence.
func (h *Hooks) BeforeOrganizationCreate(fn sdk.HookFunc[*CreateOrganizationInput]) {
	h.beforeOrgCreate.Register(fn)
}

// AfterOrganizationCreate registers a hook executed after organization and owner creation commit.
func (h *Hooks) AfterOrganizationCreate(fn sdk.HookFunc[*OrganizationRecord]) {
	h.afterOrgCreate.Register(fn)
}

// BeforeMemberAdd registers a hook executed before adding a member to an organization.
func (h *Hooks) BeforeMemberAdd(fn sdk.HookFunc[*AddMemberInput]) {
	h.beforeMemberAdd.Register(fn)
}

// AfterMemberAdd registers a hook executed after a member has been added.
func (h *Hooks) AfterMemberAdd(fn sdk.HookFunc[*Membership]) {
	h.afterMemberAdd.Register(fn)
}

func (h *Hooks) runBeforeOrgCreate(ctx context.Context, in *CreateOrganizationInput) error {
	return h.beforeOrgCreate.Execute(ctx, in)
}

func (h *Hooks) runAfterOrgCreate(ctx context.Context, org *OrganizationRecord) error {
	return h.afterOrgCreate.Execute(ctx, org)
}

func (h *Hooks) runBeforeMemberAdd(ctx context.Context, in *AddMemberInput) error {
	return h.beforeMemberAdd.Execute(ctx, in)
}

func (h *Hooks) runAfterMemberAdd(ctx context.Context, m *Membership) error {
	return h.afterMemberAdd.Execute(ctx, m)
}
