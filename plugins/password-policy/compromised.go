package passwordpolicy

import (
	"context"
	"strings"
)

// CompromisedChecker defines a function that checks whether a password is known to be breached or common.
type CompromisedChecker func(ctx context.Context, password string) (bool, error)

// CommonCompromisedPasswords contains universally known weak, leaked, and default passwords.
var CommonCompromisedPasswords = map[string]struct{}{
	"123456":        {},
	"12345678":      {},
	"123456789":     {},
	"password":      {},
	"password123":   {},
	"qwerty":        {},
	"111111":        {},
	"12345":         {},
	"1234567":       {},
	"dragon":        {},
	"welcome":       {},
	"welcome1":      {},
	"welcome123":    {},
	"admin":         {},
	"admin123":      {},
	"letmein":       {},
	"monkey":        {},
	"football":      {},
	"iloveyou":      {},
	"starwars":      {},
	"master":        {},
	"secret":        {},
	"pass1234":      {},
	"changeme":      {},
	"trustno1":      {},
	"sunshine":      {},
	"princess":      {},
	"superman":      {},
	"batman":        {},
	"charlie":       {},
	"donald":        {},
	"jordan":        {},
	"harley":        {},
	"michelle":      {},
	"shadow":        {},
	"hunter2":       {},
}

// DefaultCompromisedChecker checks if the candidate password exists in CommonCompromisedPasswords.
func DefaultCompromisedChecker(_ context.Context, password string) (bool, error) {
	lower := strings.ToLower(strings.TrimSpace(password))
	_, found := CommonCompromisedPasswords[lower]
	return found, nil
}
