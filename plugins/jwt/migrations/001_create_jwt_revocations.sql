-- Migration: 001_create_jwt_revocations.sql
-- Description: Creates tables and indexes for individual token and subject-wide JWT revocations.

CREATE TABLE IF NOT EXISTS jwt_token_revocations (
    jti VARCHAR(255) PRIMARY KEY,
    subject VARCHAR(255),
    reason TEXT,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_jwt_token_revocations_exp
    ON jwt_token_revocations (expires_at);

CREATE TABLE IF NOT EXISTS jwt_subject_revocations (
    subject VARCHAR(255) PRIMARY KEY,
    cutoff TIMESTAMPTZ NOT NULL,
    reason TEXT,
    revoked_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_jwt_subject_revocations_cutoff
    ON jwt_subject_revocations (subject, cutoff);
