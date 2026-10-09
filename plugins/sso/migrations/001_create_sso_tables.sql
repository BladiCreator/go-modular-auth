-- Migration: 001_create_sso_tables.sql
-- Description: Creates persistent storage tables for enterprise SSO configurations, domains, and in-flight state sessions.

CREATE TABLE IF NOT EXISTS auth_sso_configs (
    id VARCHAR(64) PRIMARY KEY,
    organization_id VARCHAR(64) NOT NULL,
    name VARCHAR(255) NOT NULL,
    protocol VARCHAR(32) NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    domains JSONB NOT NULL DEFAULT '[]'::jsonb,
    jit_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    default_role VARCHAR(64) NOT NULL DEFAULT 'member',
    auto_link BOOLEAN NOT NULL DEFAULT FALSE,
    oidc_config JSONB NULL,
    saml_config JSONB NULL,
    attribute_mapping JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_auth_sso_configs_org ON auth_sso_configs(organization_id);

CREATE TABLE IF NOT EXISTS auth_sso_domains (
    domain VARCHAR(255) PRIMARY KEY,
    organization_id VARCHAR(64) NOT NULL,
    config_id VARCHAR(64) NOT NULL REFERENCES auth_sso_configs(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_auth_sso_domains_org ON auth_sso_domains(organization_id);

CREATE TABLE IF NOT EXISTS auth_sso_states (
    state VARCHAR(255) PRIMARY KEY,
    organization_id VARCHAR(64) NOT NULL,
    config_id VARCHAR(64) NOT NULL REFERENCES auth_sso_configs(id) ON DELETE CASCADE,
    protocol VARCHAR(32) NOT NULL,
    redirect_uri TEXT NOT NULL,
    relay_state TEXT NULL,
    nonce VARCHAR(255) NOT NULL,
    code_verifier VARCHAR(255) NULL,
    metadata JSONB NULL,
    consumed_at TIMESTAMPTZ NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_auth_sso_states_expires ON auth_sso_states(expires_at);
CREATE INDEX IF NOT EXISTS idx_auth_sso_states_consumed ON auth_sso_states(consumed_at);
