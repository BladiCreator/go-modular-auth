package twofactor

// NewServiceForTesting exports internal service construction for blackbox testing.
func NewServiceForTesting(cfg Config) TwoFactor {
	return newService(nil, cfg)
}
