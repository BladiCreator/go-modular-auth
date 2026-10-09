package policy

import "errors"

var (
	// ErrForbidden indicates that the evaluated policy explicitly or implicitly denied access.
	ErrForbidden = errors.New("access denied by policy")

	// ErrChallengeRequired indicates that additional authentication or verification is required before access can be granted.
	ErrChallengeRequired = errors.New("authentication challenge required by policy")

	// ErrPrincipalRequired indicates that a request lacked an authenticated principal when evaluation required one.
	ErrPrincipalRequired = errors.New("authenticated principal is required")

	// ErrPolicyNotFound indicates that the requested policy does not exist.
	ErrPolicyNotFound = errors.New("policy not found")

	// ErrPolicyAlreadyExists indicates that a policy with the given ID is already registered.
	ErrPolicyAlreadyExists = errors.New("policy already registered")

	// ErrInvalidRequest indicates that the evaluation request was malformed or missing mandatory fields.
	ErrInvalidRequest = errors.New("invalid authorization request")

	// ErrNoApplicablePolicy indicates that no registered policy applied to the request under a strict evaluation mode.
	ErrNoApplicablePolicy = errors.New("no applicable policy found for request")
)
