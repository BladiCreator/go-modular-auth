-- Migration: 001_create_account_linking_tables.sql
-- Description: Creates persistent storage table for ephemeral Account Linking tickets.

CREATE TABLE IF NOT EXISTS linking_tickets (
    id VARCHAR(64) PRIMARY KEY,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    user_id VARCHAR(64) NOT NULL,
    target_provider VARCHAR(64) NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    consumed_at TIMESTAMPTZ NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_linking_tickets_hash ON linking_tickets(token_hash);
CREATE INDEX IF NOT EXISTS idx_linking_tickets_user ON linking_tickets(user_id);
CREATE INDEX IF NOT EXISTS idx_linking_tickets_expires ON linking_tickets(expires_at);
