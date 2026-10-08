-- Migration: 001_create_email_otps.sql
-- Description: Creates the auth_email_otps table for GoModularAuth Email OTP plugin.
-- Compatible with PostgreSQL, SQLite, and MySQL.

CREATE TABLE IF NOT EXISTS auth_email_otps (
    id VARCHAR(64) PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    subject VARCHAR(255) NOT NULL,
    purpose VARCHAR(64) NOT NULL,
    otp_hash VARCHAR(128) NOT NULL,
    salt VARCHAR(64) NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    max_attempts INT NOT NULL DEFAULT 3,
    attempts INT NOT NULL DEFAULT 0,
    used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_auth_email_otps_email ON auth_email_otps(email);
CREATE INDEX IF NOT EXISTS idx_auth_email_otps_expires ON auth_email_otps(expires_at);
