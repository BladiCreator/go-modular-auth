package schema

// Core model names.
const (
	ModelUsers         = "users"
	ModelAccounts      = "accounts"
	ModelCredentials   = "credentials"
	ModelSessions      = "sessions"
	ModelVerifications = "verifications"
)

// UserModel returns the canonical core schema definition for the users table.
func UserModel() *Model {
	m := NewModel(ModelUsers, "users", "id")
	_ = m.AddField(Field{Name: "id", Type: TypeString, Required: true})
	_ = m.AddField(Field{Name: "email", Type: TypeString, Required: true, Unique: true})
	_ = m.AddField(Field{Name: "email_verified", DBName: "email_verified", Type: TypeBool, Default: false})
	_ = m.AddField(Field{Name: "created_at", DBName: "created_at", Type: TypeTime, Required: true})
	_ = m.AddField(Field{Name: "updated_at", DBName: "updated_at", Type: TypeTime, Required: true})
	return m
}

// AccountModel returns the canonical core schema definition for the accounts table.
func AccountModel() *Model {
	m := NewModel(ModelAccounts, "accounts", "id")
	_ = m.AddField(Field{Name: "id", Type: TypeString, Required: true})
	_ = m.AddField(Field{
		Name:     "user_id",
		DBName:   "user_id",
		Type:     TypeString,
		Required: true,
		References: &Reference{
			Model:    ModelUsers,
			Field:    "id",
			OnDelete: "CASCADE",
		},
	})
	_ = m.AddField(Field{Name: "provider", Type: TypeString, Required: true})
	_ = m.AddField(Field{Name: "provider_id", DBName: "provider_id", Type: TypeString, Required: true})
	_ = m.AddField(Field{Name: "created_at", DBName: "created_at", Type: TypeTime, Required: true})
	_ = m.AddField(Field{Name: "updated_at", DBName: "updated_at", Type: TypeTime, Required: true})

	m.Indexes = append(m.Indexes,
		Index{Name: "uq_accounts_provider", Fields: []string{"provider", "provider_id"}, Unique: true},
		Index{Name: "idx_accounts_user_id", Fields: []string{"user_id"}, Unique: false},
	)
	return m
}

// CredentialModel returns the canonical core schema definition for the credentials table.
func CredentialModel() *Model {
	m := NewModel(ModelCredentials, "credentials", "id")
	_ = m.AddField(Field{Name: "id", Type: TypeString, Required: true})
	_ = m.AddField(Field{
		Name:     "user_id",
		DBName:   "user_id",
		Type:     TypeString,
		Required: true,
		References: &Reference{
			Model:    ModelUsers,
			Field:    "id",
			OnDelete: "CASCADE",
		},
	})
	_ = m.AddField(Field{
		Name:     "account_id",
		DBName:   "account_id",
		Type:     TypeString,
		Required: true,
		References: &Reference{
			Model:    ModelAccounts,
			Field:    "id",
			OnDelete: "CASCADE",
		},
	})
	_ = m.AddField(Field{Name: "type", Type: TypeString, Required: true})
	_ = m.AddField(Field{Name: "secret", Type: TypeString, Required: true})
	_ = m.AddField(Field{Name: "created_at", DBName: "created_at", Type: TypeTime, Required: true})
	_ = m.AddField(Field{Name: "updated_at", DBName: "updated_at", Type: TypeTime, Required: true})
	_ = m.AddField(Field{Name: "revoked_at", DBName: "revoked_at", Type: TypeTime, Required: false})

	m.Indexes = append(m.Indexes,
		Index{Name: "idx_credentials_account_type", Fields: []string{"account_id", "type"}, Unique: false},
		Index{Name: "idx_credentials_user_id", Fields: []string{"user_id"}, Unique: false},
	)
	return m
}

// SessionModel returns the canonical core schema definition for the sessions table.
func SessionModel() *Model {
	m := NewModel(ModelSessions, "sessions", "id")
	_ = m.AddField(Field{Name: "id", Type: TypeString, Required: true})
	_ = m.AddField(Field{
		Name:     "user_id",
		DBName:   "user_id",
		Type:     TypeString,
		Required: true,
		References: &Reference{
			Model:    ModelUsers,
			Field:    "id",
			OnDelete: "CASCADE",
		},
	})
	_ = m.AddField(Field{Name: "token_hash", DBName: "token_hash", Type: TypeString, Required: true, Unique: true})
	_ = m.AddField(Field{Name: "ip_address", DBName: "ip_address", Type: TypeString, Required: false})
	_ = m.AddField(Field{Name: "user_agent", DBName: "user_agent", Type: TypeString, Required: false})
	_ = m.AddField(Field{Name: "expires_at", DBName: "expires_at", Type: TypeTime, Required: true})
	_ = m.AddField(Field{Name: "revoked_at", DBName: "revoked_at", Type: TypeTime, Required: false})
	_ = m.AddField(Field{Name: "created_at", DBName: "created_at", Type: TypeTime, Required: true})

	m.Indexes = append(m.Indexes,
		Index{Name: "idx_sessions_user_id", Fields: []string{"user_id"}, Unique: false},
		Index{Name: "idx_sessions_token_hash", Fields: []string{"token_hash"}, Unique: true},
	)
	return m
}

// VerificationModel returns the canonical core schema definition for the verification tokens table.
func VerificationModel() *Model {
	m := NewModel(ModelVerifications, "verifications", "id")
	_ = m.AddField(Field{Name: "id", Type: TypeString, Required: true})
	_ = m.AddField(Field{Name: "purpose", Type: TypeString, Required: true})
	_ = m.AddField(Field{Name: "subject", Type: TypeString, Required: true})
	_ = m.AddField(Field{Name: "token_hash", DBName: "token_hash", Type: TypeString, Required: true, Unique: true})
	_ = m.AddField(Field{Name: "expires_at", DBName: "expires_at", Type: TypeTime, Required: true})
	_ = m.AddField(Field{Name: "used_at", DBName: "used_at", Type: TypeTime, Required: false})
	_ = m.AddField(Field{Name: "created_at", DBName: "created_at", Type: TypeTime, Required: true})

	m.Indexes = append(m.Indexes,
		Index{Name: "idx_verifications_token_hash", Fields: []string{"token_hash"}, Unique: true},
		Index{Name: "idx_verifications_purpose_subject", Fields: []string{"purpose", "subject"}, Unique: false},
	)
	return m
}

// DefaultCoreSchema initializes and returns a Schema populated with all core models and validated.
func DefaultCoreSchema() (*Schema, error) {
	s := New()
	for _, m := range []*Model{
		UserModel(),
		AccountModel(),
		CredentialModel(),
		SessionModel(),
		VerificationModel(),
	} {
		if err := s.AddModel(m); err != nil {
			return nil, err
		}
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return s, nil
}
