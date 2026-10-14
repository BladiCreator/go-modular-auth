-- Migration: 001_create_anonymous_identities.sql
-- Description: Creates the anonymous_identities table and relevant indexes

CREATE TABLE IF NOT EXISTS anonymous_identities (
    id VARCHAR(64) PRIMARY KEY,
    user_id VARCHAR(64) NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    converted_at TIMESTAMPTZ,
    linked_user_id VARCHAR(64),
    metadata JSONB DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

-- Index for efficient cleanup queries filtering unconverted expired records
CREATE INDEX IF NOT EXISTS idx_anonymous_expires_at 
    ON anonymous_identities (expires_at) 
    WHERE converted_at IS NULL;

-- Index for lookup by Core user ID
CREATE INDEX IF NOT EXISTS idx_anonymous_user_id 
    ON anonymous_identities (user_id);
