-- Migration: 001_create_policy_tables
-- Description: Schema for policy metadata and audit evaluation records

CREATE TABLE IF NOT EXISTS auth_policies (
    id VARCHAR(128) PRIMARY KEY,
    description TEXT,
    combinator VARCHAR(32) NOT NULL DEFAULT 'deny_overrides',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS auth_policy_evaluations (
    id VARCHAR(64) PRIMARY KEY,
    principal_subject VARCHAR(128) NOT NULL,
    resource_type VARCHAR(64) NOT NULL,
    resource_id VARCHAR(128) NOT NULL,
    action VARCHAR(64) NOT NULL,
    effect VARCHAR(32) NOT NULL,
    reason TEXT,
    evaluated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_policy_eval_principal 
    ON auth_policy_evaluations(principal_subject, evaluated_at DESC);

CREATE INDEX IF NOT EXISTS idx_policy_eval_resource 
    ON auth_policy_evaluations(resource_type, resource_id);
