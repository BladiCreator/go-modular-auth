-- Migration: 001_create_passkeys.sql
-- Description: Creates auth_passkeys and auth_passkey_challenges tables for the GoModularAuth Passkey plugin.
-- Compatible with PostgreSQL, SQLite, and MySQL.

CREATE TABLE IF NOT EXISTS auth_passkeys (
    id VARCHAR(255) NOT NULL PRIMARY KEY,
    credential_id BYTEA NOT NULL,
    user_id VARCHAR(64) NOT NULL,
    friendly_name VARCHAR(255) NOT NULL DEFAULT '',
    public_key BYTEA NOT NULL,
    attestation_type VARCHAR(64) NOT NULL DEFAULT '',
    aaguid BYTEA NOT NULL DEFAULT '\x'::bytea,
    sign_count BIGINT NOT NULL DEFAULT 0,
    clone_warning BOOLEAN NOT NULL DEFAULT FALSE,
    attachment VARCHAR(64) NOT NULL DEFAULT '',
    transports TEXT NOT NULL DEFAULT '[]',
    user_present BOOLEAN NOT NULL DEFAULT TRUE,
    user_verified BOOLEAN NOT NULL DEFAULT FALSE,
    backup_eligible BOOLEAN NOT NULL DEFAULT FALSE,
    backup_state BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP WITH TIME ZONE NULL,
    revoked_at TIMESTAMP WITH TIME ZONE NULL,
    CONSTRAINT fk_auth_passkeys_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_auth_passkeys_user_id ON auth_passkeys(user_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_auth_passkeys_credential_id ON auth_passkeys(credential_id);

CREATE TABLE IF NOT EXISTS auth_passkey_challenges (
    id VARCHAR(128) NOT NULL PRIMARY KEY,
    type VARCHAR(32) NOT NULL,
    user_id VARCHAR(64) NOT NULL DEFAULT '',
    friendly_name VARCHAR(255) NOT NULL DEFAULT '',
    data TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    consumed_at TIMESTAMP WITH TIME ZONE NULL
);

CREATE INDEX IF NOT EXISTS idx_auth_passkey_challenges_expires ON auth_passkey_challenges(expires_at);
