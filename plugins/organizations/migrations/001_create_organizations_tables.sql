-- Migration: 001_create_organizations_tables.sql
-- Description: Creates organizations, memberships, teams, team memberships, and invitations tables.

-- 1. Organizations
CREATE TABLE IF NOT EXISTS organizations (
    id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(64) NOT NULL UNIQUE,
    owner_id VARCHAR(255) NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_organizations_slug
    ON organizations (slug);

CREATE INDEX IF NOT EXISTS idx_organizations_owner_id
    ON organizations (owner_id);

-- 2. Organization Memberships
CREATE TABLE IF NOT EXISTS organization_memberships (
    id VARCHAR(64) PRIMARY KEY,
    organization_id VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id VARCHAR(255) NOT NULL,
    role VARCHAR(32) NOT NULL DEFAULT 'member',
    status VARCHAR(32) NOT NULL DEFAULT 'active',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT uq_org_memberships UNIQUE (organization_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_org_memberships_user
    ON organization_memberships (user_id, status);

CREATE INDEX IF NOT EXISTS idx_org_memberships_org_role
    ON organization_memberships (organization_id, role);

-- 3. Teams
CREATE TABLE IF NOT EXISTS organization_teams (
    id VARCHAR(64) PRIMARY KEY,
    organization_id VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(64) NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CONSTRAINT uq_org_teams_slug UNIQUE (organization_id, slug)
);

CREATE INDEX IF NOT EXISTS idx_org_teams_org_id
    ON organization_teams (organization_id);

-- 4. Team Members
CREATE TABLE IF NOT EXISTS organization_team_members (
    team_id VARCHAR(64) NOT NULL REFERENCES organization_teams(id) ON DELETE CASCADE,
    user_id VARCHAR(255) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (team_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_org_team_members_user
    ON organization_team_members (user_id);

-- 5. Invitations
CREATE TABLE IF NOT EXISTS organization_invitations (
    id VARCHAR(64) PRIMARY KEY,
    organization_id VARCHAR(64) NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    role VARCHAR(32) NOT NULL DEFAULT 'member',
    inviter_user_id VARCHAR(255) NOT NULL,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    expires_at TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_org_invitations_token_hash
    ON organization_invitations (token_hash);

CREATE INDEX IF NOT EXISTS idx_org_invitations_org_email
    ON organization_invitations (organization_id, email);

CREATE INDEX IF NOT EXISTS idx_org_invitations_expires_at
    ON organization_invitations (expires_at)
    WHERE accepted_at IS NULL;
