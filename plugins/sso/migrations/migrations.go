// Package migrations exposes embedded SQL migration assets for the SSO plugin.
package migrations

import _ "embed"

//go:embed 001_create_sso_tables.sql
var SchemaSQL string
