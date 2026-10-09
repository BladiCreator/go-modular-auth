-- Migration: 001_create_audit_tables.sql
-- Description: Creates auth_audit_records table for structured security audit logging.

CREATE TABLE IF NOT EXISTS auth_audit_records (
    id VARCHAR(64) PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    event VARCHAR(255) NOT NULL,
    action VARCHAR(255) NOT NULL,
    actor_subject VARCHAR(255) NOT NULL DEFAULT '',
    actor_type VARCHAR(64) NOT NULL DEFAULT '',
    target_type VARCHAR(64) NOT NULL DEFAULT '',
    target_id VARCHAR(255) NOT NULL DEFAULT '',
    outcome VARCHAR(32) NOT NULL DEFAULT 'success',
    organization_id VARCHAR(255) NOT NULL DEFAULT '',
    ip_address VARCHAR(128) NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT '',
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    error_message TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_auth_audit_timestamp
    ON auth_audit_records (timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_auth_audit_actor
    ON auth_audit_records (actor_subject);

CREATE INDEX IF NOT EXISTS idx_auth_audit_target
    ON auth_audit_records (target_type, target_id);

CREATE INDEX IF NOT EXISTS idx_auth_audit_org_ts
    ON auth_audit_records (organization_id, timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_auth_audit_event
    ON auth_audit_records (event);
