// Package migrations contains SQL schema migrations for the audit plugin.
package migrations

import (
	_ "embed"

	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
)

//go:embed 001_create_audit_tables.sql
var SchemaSQL string

// Migrations returns the slice of schema migrations for the audit module.
func Migrations() []sdk.Migration {
	return []sdk.Migration{
		{
			Version:     1,
			Description: "create auth_audit_records table",
		},
	}
}
