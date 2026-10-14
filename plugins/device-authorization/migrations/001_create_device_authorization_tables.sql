-- Migration: 001_create_device_authorization_tables.sql
-- Description: Creates device_grants table for RFC 8628 OAuth 2.0 Device Authorization Grant sessions.

CREATE TABLE IF NOT EXISTS device_grants (
    id VARCHAR(64) PRIMARY KEY,
    client_id VARCHAR(255) NOT NULL,
    device_code_hash VARCHAR(64) NOT NULL UNIQUE,
    user_code VARCHAR(32) NOT NULL UNIQUE,
    status VARCHAR(32) NOT NULL DEFAULT 'pending',
    user_id VARCHAR(255) NOT NULL DEFAULT '',
    scope TEXT NOT NULL DEFAULT '',
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    expires_at TIMESTAMPTZ NOT NULL,
    last_polled_at TIMESTAMPTZ,
    polling_interval INT NOT NULL DEFAULT 5,
    failed_attempts INT NOT NULL DEFAULT 0,
    authorized_at TIMESTAMPTZ,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_device_grants_device_hash
    ON device_grants (device_code_hash);

CREATE UNIQUE INDEX IF NOT EXISTS idx_device_grants_user_code
    ON device_grants (user_code);

CREATE INDEX IF NOT EXISTS idx_device_grants_client_id
    ON device_grants (client_id);

CREATE INDEX IF NOT EXISTS idx_device_grants_expires_at
    ON device_grants (expires_at);
