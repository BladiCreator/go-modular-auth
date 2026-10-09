// Package migrations provides embedded SQL migrations for the SAML plugin.
package migrations

import _ "embed"

//go:embed 001_create_saml_tables.sql
var SchemaSQL string
