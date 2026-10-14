-- Migration 001: Create phone identity and phone OTP verification tables

CREATE TABLE IF NOT EXISTS phones (
    id VARCHAR(64) PRIMARY KEY,
    user_id VARCHAR(64) NOT NULL,
    phone_number VARCHAR(32) NOT NULL,
    verified BOOLEAN NOT NULL DEFAULT FALSE,
    verified_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT uq_phones_user_id UNIQUE (user_id),
    CONSTRAINT uq_phones_phone_number UNIQUE (phone_number)
);

CREATE INDEX IF NOT EXISTS idx_phones_phone_number ON phones (phone_number);
CREATE INDEX IF NOT EXISTS idx_phones_user_id ON phones (user_id);

CREATE TABLE IF NOT EXISTS phone_otps (
    id VARCHAR(64) PRIMARY KEY,
    phone_number VARCHAR(32) NOT NULL,
    subject VARCHAR(64) NOT NULL,
    purpose VARCHAR(64) NOT NULL,
    otp_hash VARCHAR(128) NOT NULL,
    salt VARCHAR(64) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    max_attempts INT NOT NULL DEFAULT 3,
    attempts INT NOT NULL DEFAULT 0,
    used_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_phone_otps_active ON phone_otps (phone_number, purpose, expires_at) WHERE used_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_phone_otps_cleanup ON phone_otps (expires_at);
