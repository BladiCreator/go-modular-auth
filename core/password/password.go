// Package password abstracts password hashing behind the Hasher interface and
// ships an Argon2id implementation as the secure default.
package password

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/argon2"
)

var randReader io.Reader = rand.Reader

// SetRandReaderForTesting overrides the entropy source during unit tests and returns a restore func.
func SetRandReaderForTesting(r io.Reader) func() {
	prev := randReader
	randReader = r
	return func() {
		randReader = prev
	}
}

var (
	// ErrMismatch is returned by Hasher.Verify when the password does not match the hash.
	ErrMismatch = errors.New("password: hash and password do not match")
	// ErrInvalidHash is returned when an encoded hash cannot be parsed.
	ErrInvalidHash = errors.New("password: invalid encoded hash")
	// ErrIncompatibleVersion is returned when the hash was produced by another Argon2 version.
	ErrIncompatibleVersion = errors.New("password: incompatible argon2 version")
)

// Hasher hashes and verifies passwords. Implementations must be safe for
// concurrent use and must return ErrMismatch for wrong passwords.
type Hasher interface {
	Hash(ctx context.Context, password string) (string, error)
	Verify(ctx context.Context, hash, password string) error
}

// Argon2idParams configures the Argon2id hasher.
type Argon2idParams struct {
	Memory      uint32 // KiB
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

// DefaultArgon2idParams follows the OWASP Password Storage recommendation
// (m=19 MiB, t=2, p=1).
var DefaultArgon2idParams = Argon2idParams{
	Memory:      19 * 1024,
	Iterations:  2,
	Parallelism: 1,
	SaltLength:  16,
	KeyLength:   32,
}

// Argon2id is a Hasher producing PHC formatted strings:
//
//	$argon2id$v=19$m=19456,t=2,p=1$<salt>$<key>
//
// Verification reads parameters from the hash itself, so parameters can be
// raised over time without invalidating existing hashes.
type Argon2id struct {
	params Argon2idParams
}

// NewArgon2id returns an Argon2id hasher. Zero-valued fields fall back to DefaultArgon2idParams.
func NewArgon2id(params Argon2idParams) *Argon2id {
	d := DefaultArgon2idParams
	if params.Memory == 0 {
		params.Memory = d.Memory
	}
	if params.Iterations == 0 {
		params.Iterations = d.Iterations
	}
	if params.Parallelism == 0 {
		params.Parallelism = d.Parallelism
	}
	if params.SaltLength == 0 {
		params.SaltLength = d.SaltLength
	}
	if params.KeyLength == 0 {
		params.KeyLength = d.KeyLength
	}
	return &Argon2id{params: params}
}

// Hash derives an Argon2id hash with a random salt.
func (h *Argon2id) Hash(ctx context.Context, password string) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	p := h.params
	salt := make([]byte, p.SaltLength)
	if _, err := io.ReadFull(randReader, salt); err != nil {
		return "", fmt.Errorf("password: failed to read salt entropy: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)
	b64 := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.Memory, p.Iterations, p.Parallelism,
		b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// Verify compares a password against an encoded hash in constant time.
func (h *Argon2id) Verify(ctx context.Context, encoded, password string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p, salt, key, err := decode(encoded)
	if err != nil {
		return err
	}
	other := argon2.IDKey([]byte(password), salt, p.Iterations, p.Memory, p.Parallelism, uint32(len(key)))
	if subtle.ConstantTimeCompare(key, other) != 1 {
		return ErrMismatch
	}
	return nil
}

func decode(encoded string) (Argon2idParams, []byte, []byte, error) {
	var p Argon2idParams
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return p, nil, nil, ErrInvalidHash
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
		return p, nil, nil, ErrInvalidHash
	}
	if version != argon2.Version {
		return p, nil, nil, ErrIncompatibleVersion
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Iterations, &p.Parallelism); err != nil {
		return p, nil, nil, ErrInvalidHash
	}
	b64 := base64.RawStdEncoding
	salt, err := b64.DecodeString(parts[4])
	if err != nil {
		return p, nil, nil, ErrInvalidHash
	}
	key, err := b64.DecodeString(parts[5])
	if err != nil || len(key) == 0 {
		return p, nil, nil, ErrInvalidHash
	}
	return p, salt, key, nil
}
