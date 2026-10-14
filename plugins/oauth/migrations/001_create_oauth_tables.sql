-- 001_create_oauth_tables.sql
-- Schema migration for GoModularAuth OAuth plugin

CREATE TABLE IF NOT EXISTS oauth_states (
    state VARCHAR(128) PRIMARY KEY,
    provider VARCHAR(64) NOT NULL,
    redirect_uri TEXT NOT NULL,
    code_verifier TEXT,
    action VARCHAR(32) NOT NULL,
    user_id VARCHAR(64),
    metadata JSONB DEFAULT '{}'::jsonb,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL
);

-- Index for background cleanup of expired OAuth state sessions
CREATE INDEX IF NOT EXISTS idx_oauth_states_expires_at ON oauth_states (expires_at);

-- Index for querying states associated with user linking ceremonies
CREATE INDEX IF NOT EXISTS idx_oauth_states_user_id ON oauth_states (user_id) WHERE user_id IS NOT NULL;
