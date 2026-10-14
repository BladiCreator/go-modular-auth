package stripe

import (
	"context"

	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
	"github.com/BladiCreator/go-modular-auth/user"
)

// registerUserHooks registers core lifecycle hooks for auto-provisioning customers.
func registerUserHooks(ctx *sdk.Context, svc *service) {
	hooks := ctx.Hooks()
	if hooks == nil {
		return
	}

	hooks.AfterUserCreate(func(hookCtx context.Context, u *user.User) {
		if u == nil || u.ID == "" {
			return
		}

		target := TargetReference{
			Type: ReferenceUser,
			ID:   u.ID,
		}

		// Auto-provision customer in Stripe and record locally.
		_, err := svc.CreateCustomer(hookCtx, target)
		if err != nil {
			ctx.Logger().Error("stripe: failed to auto-provision customer on user create",
				"user_id", u.ID,
				"error", err,
			)
		}
	})
}
