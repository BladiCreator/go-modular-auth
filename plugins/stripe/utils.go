package stripe

import (
	"strings"
)

// GetPlanByID resolves a configured plan matching the given plan ID.
func GetPlanByID(cfg Config, planID string) (*StripePlan, bool) {
	if cfg.Subscription == nil {
		return nil, false
	}
	for i := range cfg.Subscription.Plans {
		if strings.EqualFold(cfg.Subscription.Plans[i].ID, planID) {
			return &cfg.Subscription.Plans[i], true
		}
	}
	return nil, false
}

// GetPlanByPriceID resolves a configured plan matching the given Stripe Price ID.
func GetPlanByPriceID(cfg Config, priceID string) (*StripePlan, bool) {
	if cfg.Subscription == nil || priceID == "" {
		return nil, false
	}
	for i := range cfg.Subscription.Plans {
		if cfg.Subscription.Plans[i].PriceID == priceID || cfg.Subscription.Plans[i].SeatPriceID == priceID {
			return &cfg.Subscription.Plans[i], true
		}
	}
	return nil, false
}

// GetPlanByLookupKey resolves a configured plan matching the given Stripe lookup key.
func GetPlanByLookupKey(cfg Config, lookupKey string) (*StripePlan, bool) {
	if cfg.Subscription == nil || lookupKey == "" {
		return nil, false
	}
	for i := range cfg.Subscription.Plans {
		if strings.EqualFold(cfg.Subscription.Plans[i].LookupKey, lookupKey) {
			return &cfg.Subscription.Plans[i], true
		}
	}
	return nil, false
}

// IsActiveOrTrialing returns true if the subscription is currently active or trialing.
func IsActiveOrTrialing(sub *Subscription) bool {
	if sub == nil {
		return false
	}
	return sub.Status == StatusActive || sub.Status == StatusTrialing
}

// EscapeStripeSearchValue safely escapes special characters for Stripe Search API queries.
func EscapeStripeSearchValue(val string) string {
	r := strings.NewReplacer(
		"\\", "\\\\",
		"\"", "\\\"",
		"'", "\\'",
	)
	return r.Replace(val)
}
