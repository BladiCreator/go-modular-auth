-- Migration: 001_create_session_metadata
-- Description: Create session_metadata table for optional session and device metadata
-- Database engines: PostgreSQL, SQLite, MySQL 8.0+

CREATE TABLE IF NOT EXISTS session_metadata (
    session_id      VARCHAR(64) PRIMARY KEY,
    user_id         VARCHAR(64) NOT NULL,
    device_name     VARCHAR(255),
    device_type     VARCHAR(64),
    device_os       VARCHAR(64),
    device_browser  VARCHAR(64),
    device_ip       VARCHAR(64),
    custom_metadata TEXT,
    created_at      TIMESTAMP WITH TIME ZONE NOT NULL,
    updated_at      TIMESTAMP WITH TIME ZONE NOT NULL,
    CONSTRAINT fk_session_metadata_session
        FOREIGN KEY (session_id) REFERENCES sessions(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_session_metadata_user_id ON session_metadata(user_id);
