// Package migrations embeds SQL migrations for the Account Linking plugin.
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
