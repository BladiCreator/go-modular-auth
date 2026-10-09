package migrations

import _ "embed"

//go:embed 001_create_rbac_tables.sql
var CreateRBACTablesSQL string
