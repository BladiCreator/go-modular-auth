-- Migration: 001_create_bearer_tokens.sql
-- Description: Creates the bearer_tokens table and indexes for fast lookup and cleanup.

CREATE TABLE IF NOT EXISTS bearer_tokens (
    id VARCHAR(64) PRIMARY KEY,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    subject VARCHAR(255) NOT NULL,
    principal_type VARCHAR(64) NOT NULL DEFAULT 'user',
    scopes JSONB NOT NULL DEFAULT '[]'::jsonb,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

-- Unique index for fast O(1) authentication lookup by SHA-256 token hash
CREATE UNIQUE INDEX IF NOT EXISTS idx_bearer_token_hash 
    ON bearer_tokens (token_hash);

-- Index for querying and revoking tokens by subject (user / service account)
CREATE INDEX IF NOT EXISTS idx_bearer_subject 
    ON bearer_tokens (subject);

-- Partial index for fast cleanup and purging of expired active tokens
CREATE INDEX IF NOT EXISTS idx_bearer_expires_at 
    ON bearer_tokens (expires_at) 
    WHERE revoked_at IS NULL;

-- Index for auditing and purging revoked tokens
CREATE INDEX IF NOT EXISTS idx_bearer_revoked_at 
    ON bearer_tokens (revoked_at) 
    WHERE revoked_at IS NOT NULL;
