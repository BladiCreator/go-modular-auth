-- Migration: 001_create_oidc_tables.sql
-- Description: Creates auth_oidc_states table for OpenID Connect state sessions and single-use redemption.

CREATE TABLE IF NOT EXISTS auth_oidc_states (
    state VARCHAR(128) PRIMARY KEY,
    provider VARCHAR(64) NOT NULL,
    redirect_uri TEXT NOT NULL,
    code_verifier VARCHAR(128) NOT NULL,
    nonce VARCHAR(128) NOT NULL,
    action VARCHAR(32) NOT NULL DEFAULT 'sign_in',
    user_id VARCHAR(64) NOT NULL DEFAULT '',
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    consumed_at TIMESTAMPTZ,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_auth_oidc_states_expires_at
    ON auth_oidc_states (expires_at);

CREATE INDEX IF NOT EXISTS idx_auth_oidc_states_user_id
    ON auth_oidc_states (user_id);
