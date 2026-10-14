-- Migration: 001_create_rbac_tables
-- Description: Schema for RBAC roles, permissions, and principal assignments

CREATE TABLE IF NOT EXISTS rbac_roles (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(128) UNIQUE NOT NULL,
    description TEXT,
    scope VARCHAR(32) NOT NULL,
    permissions JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_rbac_roles_scope 
    ON rbac_roles(scope);

CREATE TABLE IF NOT EXISTS rbac_assignments (
    id VARCHAR(64) PRIMARY KEY,
    role_id VARCHAR(64) NOT NULL REFERENCES rbac_roles(id) ON DELETE RESTRICT,
    principal_subject VARCHAR(128) NOT NULL,
    principal_type VARCHAR(64) NOT NULL,
    scope VARCHAR(32) NOT NULL,
    scope_id VARCHAR(128) NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uq_rbac_assignment UNIQUE(role_id, principal_subject, principal_type, scope, scope_id)
);

CREATE INDEX IF NOT EXISTS idx_rbac_assignments_principal 
    ON rbac_assignments(principal_subject, principal_type);

CREATE INDEX IF NOT EXISTS idx_rbac_assignments_scope 
    ON rbac_assignments(scope, scope_id);
