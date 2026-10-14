package jwt

import (
	"time"

	"github.com/BladiCreator/go-modular-auth/schema"
)

// RevocationRecord represents an explicit token revocation by unique ID (jti).
type RevocationRecord struct {
	JTI       string    `json:"jti"`
	Subject   string    `json:"subject,omitempty"`
	Reason    string    `json:"reason,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
	RevokedAt time.Time `json:"revoked_at"`
}

// SubjectRevocationRecord represents a blanket revocation for all tokens of a subject issued before Cutoff.
type SubjectRevocationRecord struct {
	Subject   string    `json:"subject"`
	Cutoff    time.Time `json:"cutoff"`
	Reason    string    `json:"reason,omitempty"`
	RevokedAt time.Time `json:"revoked_at"`
}

const (
	ModelJWTRevocations        = "jwt_revocations"
	ModelJWTSubjectRevocations = "jwt_subject_revocations"
)

// RegisterSchema registers the JWT revocation models into the compiled schema.
func RegisterSchema(s *schema.Schema) error {
	mRev := schema.NewModel(ModelJWTRevocations, ModelJWTRevocations, "jti")
	_ = mRev.AddField(schema.Field{Name: "jti", Type: schema.TypeString, Required: true})
	_ = mRev.AddField(schema.Field{Name: "subject", Type: schema.TypeString})
	_ = mRev.AddField(schema.Field{Name: "reason", Type: schema.TypeString})
	_ = mRev.AddField(schema.Field{Name: "expires_at", Type: schema.TypeTime, Required: true})
	_ = mRev.AddField(schema.Field{Name: "revoked_at", Type: schema.TypeTime, Required: true})

	mRev.Indexes = []schema.Index{
		{Name: "idx_jwt_rev_expires_at", Fields: []string{"expires_at"}},
	}

	if err := s.AddModel(mRev); err != nil {
		return err
	}

	mSub := schema.NewModel(ModelJWTSubjectRevocations, ModelJWTSubjectRevocations, "subject")
	_ = mSub.AddField(schema.Field{Name: "subject", Type: schema.TypeString, Required: true})
	_ = mSub.AddField(schema.Field{Name: "cutoff", Type: schema.TypeTime, Required: true})
	_ = mSub.AddField(schema.Field{Name: "reason", Type: schema.TypeString})
	_ = mSub.AddField(schema.Field{Name: "revoked_at", Type: schema.TypeTime, Required: true})

	return s.AddModel(mSub)
}
