package polar

import "github.com/BladiCreator/go-modular-auth/schema"

const (
	// ModelPolarCustomers is the registered model name for Polar customers.
	ModelPolarCustomers = "polar_customers"

	// ModelPolarSubscriptions is the registered model name for Polar subscriptions.
	ModelPolarSubscriptions = "polar_subscriptions"

	// ModelPolarBenefits is the registered model name for Polar benefits and entitlements.
	ModelPolarBenefits = "polar_benefits"
)

// RegisterSchema contributes Polar models to the compiled engine schema.
func RegisterSchema(s *schema.Schema) error {
	// 1. polar_customers
	cust := schema.NewModel(ModelPolarCustomers, ModelPolarCustomers, "id")
	_ = cust.AddField(schema.Field{Name: "id", Type: schema.TypeString, Required: true})
	_ = cust.AddField(schema.Field{Name: "reference_id", Type: schema.TypeString, Required: true})
	_ = cust.AddField(schema.Field{Name: "reference_type", Type: schema.TypeString, Required: true})
	_ = cust.AddField(schema.Field{Name: "polar_customer_id", Type: schema.TypeString, Required: true, Unique: true})
	_ = cust.AddField(schema.Field{Name: "email", Type: schema.TypeString, Required: true})
	_ = cust.AddField(schema.Field{Name: "metadata", Type: schema.TypeJSON})
	_ = cust.AddField(schema.Field{Name: "created_at", Type: schema.TypeTime, Required: true})
	_ = cust.AddField(schema.Field{Name: "updated_at", Type: schema.TypeTime, Required: true})

	cust.Indexes = []schema.Index{
		{Name: "idx_polar_cust_ref", Fields: []string{"reference_type", "reference_id"}},
		{Name: "idx_polar_cust_polar_id", Fields: []string{"polar_customer_id"}, Unique: true},
	}

	if err := s.AddModel(cust); err != nil {
		return err
	}

	// 2. polar_subscriptions
	sub := schema.NewModel(ModelPolarSubscriptions, ModelPolarSubscriptions, "id")
	_ = sub.AddField(schema.Field{Name: "id", Type: schema.TypeString, Required: true})
	_ = sub.AddField(schema.Field{Name: "customer_id", Type: schema.TypeString, Required: true})
	_ = sub.AddField(schema.Field{Name: "reference_id", Type: schema.TypeString, Required: true})
	_ = sub.AddField(schema.Field{Name: "reference_type", Type: schema.TypeString, Required: true})
	_ = sub.AddField(schema.Field{Name: "polar_subscription_id", Type: schema.TypeString, Required: true, Unique: true})
	_ = sub.AddField(schema.Field{Name: "polar_product_id", Type: schema.TypeString, Required: true})
	_ = sub.AddField(schema.Field{Name: "status", Type: schema.TypeString, Required: true})
	_ = sub.AddField(schema.Field{Name: "current_period_end", Type: schema.TypeTime})
	_ = sub.AddField(schema.Field{Name: "cancel_at_period_end", Type: schema.TypeBool, Required: true})
	_ = sub.AddField(schema.Field{Name: "metadata", Type: schema.TypeJSON})
	_ = sub.AddField(schema.Field{Name: "created_at", Type: schema.TypeTime, Required: true})
	_ = sub.AddField(schema.Field{Name: "updated_at", Type: schema.TypeTime, Required: true})

	sub.Indexes = []schema.Index{
		{Name: "idx_polar_sub_ref", Fields: []string{"reference_type", "reference_id"}},
		{Name: "idx_polar_sub_status", Fields: []string{"status"}},
	}

	if err := s.AddModel(sub); err != nil {
		return err
	}

	// 3. polar_benefits
	ben := schema.NewModel(ModelPolarBenefits, ModelPolarBenefits, "id")
	_ = ben.AddField(schema.Field{Name: "id", Type: schema.TypeString, Required: true})
	_ = ben.AddField(schema.Field{Name: "customer_id", Type: schema.TypeString, Required: true})
	_ = ben.AddField(schema.Field{Name: "reference_id", Type: schema.TypeString, Required: true})
	_ = ben.AddField(schema.Field{Name: "polar_benefit_id", Type: schema.TypeString, Required: true})
	_ = ben.AddField(schema.Field{Name: "type", Type: schema.TypeString, Required: true})
	_ = ben.AddField(schema.Field{Name: "is_granted", Type: schema.TypeBool, Required: true})
	_ = ben.AddField(schema.Field{Name: "properties", Type: schema.TypeJSON})
	_ = ben.AddField(schema.Field{Name: "created_at", Type: schema.TypeTime, Required: true})
	_ = ben.AddField(schema.Field{Name: "updated_at", Type: schema.TypeTime, Required: true})

	ben.Indexes = []schema.Index{
		{Name: "idx_polar_ben_ref", Fields: []string{"reference_id"}},
		{Name: "idx_polar_ben_id", Fields: []string{"polar_benefit_id"}},
	}

	return s.AddModel(ben)
}
