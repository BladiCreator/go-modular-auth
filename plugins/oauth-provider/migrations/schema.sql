-- Schema definition for GoModularAuth OAuth 2.1 Provider Plugin

CREATE TABLE IF NOT EXISTS oauth_clients (
    id VARCHAR(64) PRIMARY KEY,
    secret_hash VARCHAR(255),
    name VARCHAR(255) NOT NULL,
    client_type VARCHAR(32) NOT NULL,
    redirect_uris TEXT NOT NULL,
    allowed_grant_types TEXT NOT NULL,
    allowed_scopes TEXT NOT NULL,
    status VARCHAR(32) NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS oauth_authorization_codes (
    id VARCHAR(64) PRIMARY KEY,
    code_hash VARCHAR(128) NOT NULL UNIQUE,
    client_id VARCHAR(64) NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    user_id VARCHAR(64) NOT NULL,
    redirect_uri TEXT NOT NULL,
    scopes TEXT NOT NULL,
    code_challenge VARCHAR(255) NOT NULL,
    code_challenge_method VARCHAR(32) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_oauth_codes_lookup ON oauth_authorization_codes(code_hash);

CREATE TABLE IF NOT EXISTS oauth_access_tokens (
    id VARCHAR(64) PRIMARY KEY,
    token_hash VARCHAR(128) NOT NULL UNIQUE,
    client_id VARCHAR(64) NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    user_id VARCHAR(64),
    scopes TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_oauth_access_tokens_hash ON oauth_access_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_oauth_access_tokens_client ON oauth_access_tokens(client_id);
CREATE INDEX IF NOT EXISTS idx_oauth_access_tokens_user ON oauth_access_tokens(user_id);

CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
    id VARCHAR(64) PRIMARY KEY,
    token_hash VARCHAR(128) NOT NULL UNIQUE,
    access_token_id VARCHAR(64) NOT NULL,
    client_id VARCHAR(64) NOT NULL REFERENCES oauth_clients(id) ON DELETE CASCADE,
    user_id VARCHAR(64),
    scopes TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_oauth_refresh_tokens_hash ON oauth_refresh_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_oauth_refresh_tokens_client ON oauth_refresh_tokens(client_id);
CREATE INDEX IF NOT EXISTS idx_oauth_refresh_tokens_user ON oauth_refresh_tokens(user_id);
