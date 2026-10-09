-- Migration: 001_create_saml_tables.sql
-- Description: Creates persistent storage tables for SAML IdP configurations, request sessions, and assertion replay tracking.

CREATE TABLE IF NOT EXISTS auth_saml_idps (
    id VARCHAR(64) PRIMARY KEY,
    organization_id VARCHAR(64) NULL,
    entity_id VARCHAR(255) NOT NULL UNIQUE,
    sso_url TEXT NOT NULL,
    slo_url TEXT NULL,
    certificates JSONB NOT NULL DEFAULT '[]'::jsonb,
    sp_entity_id VARCHAR(255) NULL,
    acs_url TEXT NULL,
    name_id_format VARCHAR(255) NULL,
    sign_request BOOLEAN NOT NULL DEFAULT FALSE,
    allow_unsolicited BOOLEAN NOT NULL DEFAULT FALSE,
    clock_skew_nanos BIGINT NOT NULL DEFAULT 120000000000,
    attribute_mapping JSONB NOT NULL DEFAULT '{}'::jsonb,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_auth_saml_idps_org ON auth_saml_idps(organization_id);

CREATE TABLE IF NOT EXISTS auth_saml_requests (
    id VARCHAR(255) PRIMARY KEY,
    relay_state VARCHAR(255) NOT NULL,
    provider_id VARCHAR(64) NOT NULL REFERENCES auth_saml_idps(id) ON DELETE CASCADE,
    organization_id VARCHAR(64) NULL,
    redirect_uri TEXT NULL,
    consumed_at TIMESTAMPTZ NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_auth_saml_requests_expires ON auth_saml_requests(expires_at);
CREATE INDEX IF NOT EXISTS idx_auth_saml_requests_relay ON auth_saml_requests(relay_state);

CREATE TABLE IF NOT EXISTS auth_saml_assertions (
    assertion_id VARCHAR(255) PRIMARY KEY,
    provider_id VARCHAR(64) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_auth_saml_assertions_expires ON auth_saml_assertions(expires_at);
