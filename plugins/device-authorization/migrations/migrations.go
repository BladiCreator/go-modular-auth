// Package migrations contains SQL schema migrations for the device-authorization plugin.
package migrations

import (
	_ "embed"

	sdk "github.com/BladiCreator/go-modular-auth/plugin-sdk"
)

//go:embed 001_create_device_authorization_tables.sql
var SchemaSQL string

// Migrations returns the slice of schema migrations for the device-authorization module.
func Migrations() []sdk.Migration {
	return []sdk.Migration{
		{
			Version:     1,
			Description: "create device_grants table",
		},
	}
}
