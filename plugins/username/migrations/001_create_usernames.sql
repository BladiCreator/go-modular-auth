-- Migration: 001_create_usernames.sql
-- Description: Creates the auth_usernames table for the GoModularAuth username plugin.
-- Compatible with PostgreSQL, SQLite, and MySQL.

CREATE TABLE IF NOT EXISTS auth_usernames (
    user_id VARCHAR(64) NOT NULL PRIMARY KEY,
    username VARCHAR(64) NOT NULL,
    normalized VARCHAR(64) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_auth_usernames_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_auth_usernames_normalized ON auth_usernames(normalized);
