-- Migration: 001_create_admin_tables.sql
-- Description: Creates auth_admin_users table for storing administrative user metadata, disabled flags, and roles.

CREATE TABLE IF NOT EXISTS auth_admin_users (
    user_id VARCHAR(255) PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    disabled BOOLEAN NOT NULL DEFAULT false,
    disabled_at TIMESTAMPTZ,
    disabled_reason TEXT NOT NULL DEFAULT '',
    is_admin BOOLEAN NOT NULL DEFAULT false,
    role VARCHAR(64) NOT NULL DEFAULT '',
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_auth_admin_users_email
    ON auth_admin_users (email);

CREATE INDEX IF NOT EXISTS idx_auth_admin_users_disabled
    ON auth_admin_users (disabled);

CREATE INDEX IF NOT EXISTS idx_auth_admin_users_is_admin
    ON auth_admin_users (is_admin);

CREATE INDEX IF NOT EXISTS idx_auth_admin_users_created_at
    ON auth_admin_users (created_at DESC);
