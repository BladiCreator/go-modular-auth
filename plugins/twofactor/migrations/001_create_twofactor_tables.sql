-- Migration: 001_create_twofactor_tables.sql
-- Description: Create persistent tables for factors, recovery codes and MFA challenges.

CREATE TABLE IF NOT EXISTS twofactor_factors (
    id VARCHAR(64) PRIMARY KEY,
    user_id VARCHAR(64) NOT NULL,
    type VARCHAR(32) NOT NULL,
    label VARCHAR(128),
    encrypted_secret TEXT NOT NULL,
    confirmed BOOLEAN NOT NULL DEFAULT FALSE,
    confirmed_at TIMESTAMP WITH TIME ZONE,
    last_used_at TIMESTAMP WITH TIME ZONE,
    last_used_time_step BIGINT NOT NULL DEFAULT -1,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_twofactor_factors_user ON twofactor_factors (user_id);
CREATE INDEX IF NOT EXISTS idx_twofactor_factors_user_confirmed ON twofactor_factors (user_id, confirmed);

CREATE TABLE IF NOT EXISTS twofactor_recovery_codes (
    id VARCHAR(64) PRIMARY KEY,
    user_id VARCHAR(64) NOT NULL,
    code_hash VARCHAR(128) NOT NULL,
    used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_twofactor_recovery_codes_user ON twofactor_recovery_codes (user_id);
CREATE INDEX IF NOT EXISTS idx_twofactor_recovery_codes_hash ON twofactor_recovery_codes (user_id, code_hash);

CREATE TABLE IF NOT EXISTS twofactor_challenges (
    id VARCHAR(64) PRIMARY KEY,
    user_id VARCHAR(64) NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_twofactor_challenges_user ON twofactor_challenges (user_id);
