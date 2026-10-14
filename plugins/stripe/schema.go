package stripe

import "github.com/BladiCreator/go-modular-auth/schema"

const (
	// ModelStripeCustomers is the registered model name for Stripe customers.
	ModelStripeCustomers = "stripe_customers"

	// ModelStripeSubscriptions is the registered model name for Stripe subscriptions.
	ModelStripeSubscriptions = "stripe_subscriptions"
)

// RegisterSchema contributes the Stripe models to the compiled engine schema.
func RegisterSchema(s *schema.Schema) error {
	// 1. stripe_customers
	cust := schema.NewModel(ModelStripeCustomers, ModelStripeCustomers, "id")
	_ = cust.AddField(schema.Field{Name: "id", Type: schema.TypeString, Required: true})
	_ = cust.AddField(schema.Field{Name: "reference_id", Type: schema.TypeString, Required: true})
	_ = cust.AddField(schema.Field{Name: "reference_type", Type: schema.TypeString, Required: true})
	_ = cust.AddField(schema.Field{Name: "stripe_customer_id", Type: schema.TypeString, Required: true, Unique: true})
	_ = cust.AddField(schema.Field{Name: "email", Type: schema.TypeString, Required: true})
	_ = cust.AddField(schema.Field{Name: "metadata", Type: schema.TypeJSON})
	_ = cust.AddField(schema.Field{Name: "created_at", Type: schema.TypeTime, Required: true})
	_ = cust.AddField(schema.Field{Name: "updated_at", Type: schema.TypeTime, Required: true})

	cust.Indexes = []schema.Index{
		{Name: "idx_stripe_cust_ref", Fields: []string{"reference_type", "reference_id"}},
		{Name: "idx_stripe_cust_stripe_id", Fields: []string{"stripe_customer_id"}, Unique: true},
	}

	if err := s.AddModel(cust); err != nil {
		return err
	}

	// 2. stripe_subscriptions
	sub := schema.NewModel(ModelStripeSubscriptions, ModelStripeSubscriptions, "id")
	_ = sub.AddField(schema.Field{Name: "id", Type: schema.TypeString, Required: true})
	_ = sub.AddField(schema.Field{Name: "customer_id", Type: schema.TypeString, Required: true})
	_ = sub.AddField(schema.Field{Name: "reference_id", Type: schema.TypeString, Required: true})
	_ = sub.AddField(schema.Field{Name: "reference_type", Type: schema.TypeString, Required: true})
	_ = sub.AddField(schema.Field{Name: "stripe_subscription_id", Type: schema.TypeString, Required: true, Unique: true})
	_ = sub.AddField(schema.Field{Name: "stripe_price_id", Type: schema.TypeString, Required: true})
	_ = sub.AddField(schema.Field{Name: "status", Type: schema.TypeString, Required: true})
	_ = sub.AddField(schema.Field{Name: "seats", Type: schema.TypeInt64})
	_ = sub.AddField(schema.Field{Name: "cancel_at_period_end", Type: schema.TypeBool, Required: true})
	_ = sub.AddField(schema.Field{Name: "current_period_start", Type: schema.TypeTime, Required: true})
	_ = sub.AddField(schema.Field{Name: "current_period_end", Type: schema.TypeTime, Required: true})
	_ = sub.AddField(schema.Field{Name: "metadata", Type: schema.TypeJSON})
	_ = sub.AddField(schema.Field{Name: "created_at", Type: schema.TypeTime, Required: true})
	_ = sub.AddField(schema.Field{Name: "updated_at", Type: schema.TypeTime, Required: true})

	sub.Indexes = []schema.Index{
		{Name: "idx_stripe_sub_ref", Fields: []string{"reference_type", "reference_id"}},
		{Name: "idx_stripe_sub_status", Fields: []string{"status"}},
	}

	return s.AddModel(sub)
}
