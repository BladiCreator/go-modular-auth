-- Migration: 001_create_apikeys_tables.sql
-- Description: Creates persistent table and indexes for GoModularAuth API keys plugin.

CREATE TABLE IF NOT EXISTS auth_api_keys (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    prefix VARCHAR(32) NOT NULL,
    key_hash VARCHAR(64) NOT NULL UNIQUE,
    user_id VARCHAR(64),
    organization_id VARCHAR(64),
    service_id VARCHAR(64),
    scopes JSONB NOT NULL DEFAULT '[]'::jsonb,
    permissions JSONB NOT NULL DEFAULT '[]'::jsonb,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    last_used_ip VARCHAR(64) DEFAULT '',
    last_used_ua TEXT DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for O(1) hash lookup during API key authentication
CREATE INDEX IF NOT EXISTS idx_auth_api_keys_hash ON auth_api_keys(key_hash);

-- Multi-tenant and ownership querying indexes
CREATE INDEX IF NOT EXISTS idx_auth_api_keys_user_id ON auth_api_keys(user_id) WHERE user_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_auth_api_keys_org_id ON auth_api_keys(organization_id) WHERE organization_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_auth_api_keys_service_id ON auth_api_keys(service_id) WHERE service_id IS NOT NULL;

-- Expiration indexing for background purging
CREATE INDEX IF NOT EXISTS idx_auth_api_keys_expires_at ON auth_api_keys(expires_at) WHERE expires_at IS NOT NULL;
