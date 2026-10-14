-- Migration: 001_create_audit_tables.sql
-- Description: Creates audit_records table for structured security audit logging.

CREATE TABLE IF NOT EXISTS audit_records (
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

CREATE INDEX IF NOT EXISTS idx_audit_timestamp
    ON audit_records (timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_audit_actor
    ON audit_records (actor_subject);

CREATE INDEX IF NOT EXISTS idx_audit_target
    ON audit_records (target_type, target_id);

CREATE INDEX IF NOT EXISTS idx_audit_org_ts
    ON audit_records (organization_id, timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_audit_event
    ON audit_records (event);
