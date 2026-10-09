// Package migrations embeds SQL migrations for the Password Policy plugin.
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
