-- Migration: 001_create_password_policy_tables.sql
-- Description: Creates persistent storage table for password history records.

CREATE TABLE IF NOT EXISTS password_history (
    id VARCHAR(64) PRIMARY KEY,
    user_id VARCHAR(64) NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_password_history_user_created ON password_history(user_id, created_at DESC);
