-- =============================================================================
-- CyberGuard Database Schema
-- PostgreSQL (Neon DB) | Version: 1.0.0
-- Run this file once against your Neon DB to provision the schema.
-- =============================================================================

-- Enable required extensions
CREATE EXTENSION IF NOT EXISTS "pgcrypto";   -- gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS "citext";      -- case-insensitive email

-- =============================================================================
-- ENUMS
-- =============================================================================

DO $$ BEGIN
  CREATE TYPE tenant_status AS ENUM ('onboarding', 'active', 'suspended');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TYPE scope_type AS ENUM ('domain', 'cidr');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TYPE token_status AS ENUM ('active', 'revoked', 'expired');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TYPE user_role AS ENUM ('admin', 'viewer');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- =============================================================================
-- TABLE: tenants
-- =============================================================================

CREATE TABLE IF NOT EXISTS tenants (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    org_name            VARCHAR(255) NOT NULL,
    status              tenant_status NOT NULL DEFAULT 'onboarding',
    onboarding_step     INTEGER NOT NULL DEFAULT 1,  -- 1=scope, 2=verify, 3=m365, 4=done
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_tenants_status ON tenants(status);

-- =============================================================================
-- TABLE: users
-- =============================================================================

CREATE TABLE IF NOT EXISTS users (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    email               CITEXT NOT NULL UNIQUE,
    hashed_password     TEXT NOT NULL,
    totp_secret         TEXT,                    -- stored encrypted via app layer
    is_totp_enabled     BOOLEAN NOT NULL DEFAULT FALSE,
    is_totp_verified    BOOLEAN NOT NULL DEFAULT FALSE,
    role                user_role NOT NULL DEFAULT 'admin',
    is_active           BOOLEAN NOT NULL DEFAULT TRUE,
    last_login_at       TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_users_tenant_id ON users(tenant_id);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- =============================================================================
-- TABLE: scan_scopes
-- Strict definition of what is authorized to be scanned for each tenant.
-- =============================================================================

CREATE TABLE IF NOT EXISTS scan_scopes (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id               UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    type                    scope_type NOT NULL,
    value                   VARCHAR(255) NOT NULL,   -- e.g. "bank.ma" or "196.200.0.0/24"
    verified                BOOLEAN NOT NULL DEFAULT FALSE,
    verification_token      VARCHAR(128),            -- e.g. "cyberguard-verify=abc123..."
    verification_attempts   INTEGER NOT NULL DEFAULT 0,
    verified_at             TIMESTAMPTZ,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, value)
);

CREATE INDEX IF NOT EXISTS idx_scan_scopes_tenant_id ON scan_scopes(tenant_id);
CREATE INDEX IF NOT EXISTS idx_scan_scopes_verified ON scan_scopes(verified);

-- =============================================================================
-- TABLE: m365_credentials
-- Encrypted M365 refresh tokens. NEVER store plaintext.
-- =============================================================================

CREATE TABLE IF NOT EXISTS m365_credentials (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id                   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    ms_tenant_id                VARCHAR(255) NOT NULL,     -- Microsoft's tenant GUID
    encrypted_refresh_token     TEXT NOT NULL,             -- KMS/Fernet ciphertext
    kms_key_id                  VARCHAR(255) NOT NULL,     -- Key identifier for decryption
    granted_scopes              TEXT[] NOT NULL DEFAULT '{}',
    token_status                token_status NOT NULL DEFAULT 'active',
    connected_at                TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at                TIMESTAMPTZ,
    revoked_at                  TIMESTAMPTZ,
    UNIQUE(tenant_id)   -- One M365 connection per tenant
);

CREATE INDEX IF NOT EXISTS idx_m365_creds_tenant_id ON m365_credentials(tenant_id);
CREATE INDEX IF NOT EXISTS idx_m365_creds_status ON m365_credentials(token_status);

-- =============================================================================
-- TABLE: audit_trail
-- Immutable log of every significant action. Never UPDATE or DELETE rows here.
-- =============================================================================

CREATE TABLE IF NOT EXISTS audit_trail (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    actor_user_id   UUID REFERENCES users(id) ON DELETE SET NULL,
    action          VARCHAR(100) NOT NULL,   -- e.g. 'USER_LOGIN', 'SCOPE_ADDED'
    ip_address      INET,
    user_agent      TEXT,
    metadata        JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_trail_tenant_id ON audit_trail(tenant_id);
CREATE INDEX IF NOT EXISTS idx_audit_trail_action ON audit_trail(action);
CREATE INDEX IF NOT EXISTS idx_audit_trail_created_at ON audit_trail(created_at DESC);

-- Prevent any UPDATE/DELETE on audit_trail (immutability)
CREATE OR REPLACE RULE audit_trail_no_update AS ON UPDATE TO audit_trail DO INSTEAD NOTHING;
CREATE OR REPLACE RULE audit_trail_no_delete AS ON DELETE TO audit_trail DO INSTEAD NOTHING;

-- =============================================================================
-- TABLE: scan_jobs
-- Tracks baseline and recurring scan executions.
-- =============================================================================

DO $$ BEGIN
  CREATE TYPE job_status AS ENUM ('queued', 'running', 'completed', 'failed');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

CREATE TABLE IF NOT EXISTS scan_jobs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    job_type        VARCHAR(50) NOT NULL DEFAULT 'baseline',  -- baseline, scheduled, manual
    status          job_status NOT NULL DEFAULT 'queued',
    started_at      TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    error_message   TEXT,
    metadata        JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_scan_jobs_tenant_id ON scan_jobs(tenant_id);
CREATE INDEX IF NOT EXISTS idx_scan_jobs_status ON scan_jobs(status);

-- =============================================================================
-- ROW-LEVEL SECURITY (RLS)
-- Pattern: set app.current_tenant_id = '<uuid>' before each query session.
-- =============================================================================

-- Enable RLS on all tenant-scoped tables
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_scopes ENABLE ROW LEVEL SECURITY;
ALTER TABLE m365_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_trail ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan_jobs ENABLE ROW LEVEL SECURITY;

-- Create a helper function to read current tenant from session variable
CREATE OR REPLACE FUNCTION current_tenant_id() RETURNS UUID AS $$
BEGIN
    RETURN current_setting('app.current_tenant_id', TRUE)::UUID;
EXCEPTION WHEN others THEN
    RETURN NULL;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- RLS POLICIES: users
DROP POLICY IF EXISTS users_tenant_isolation ON users;
CREATE POLICY users_tenant_isolation ON users
    USING (tenant_id = current_tenant_id())
    WITH CHECK (tenant_id = current_tenant_id());

-- RLS POLICIES: scan_scopes
DROP POLICY IF EXISTS scan_scopes_tenant_isolation ON scan_scopes;
CREATE POLICY scan_scopes_tenant_isolation ON scan_scopes
    USING (tenant_id = current_tenant_id())
    WITH CHECK (tenant_id = current_tenant_id());

-- RLS POLICIES: m365_credentials
DROP POLICY IF EXISTS m365_credentials_tenant_isolation ON m365_credentials;
CREATE POLICY m365_credentials_tenant_isolation ON m365_credentials
    USING (tenant_id = current_tenant_id())
    WITH CHECK (tenant_id = current_tenant_id());

-- RLS POLICIES: audit_trail
DROP POLICY IF EXISTS audit_trail_tenant_isolation ON audit_trail;
CREATE POLICY audit_trail_tenant_isolation ON audit_trail
    USING (tenant_id = current_tenant_id())
    WITH CHECK (tenant_id = current_tenant_id());

-- RLS POLICIES: scan_jobs
DROP POLICY IF EXISTS scan_jobs_tenant_isolation ON scan_jobs;
CREATE POLICY scan_jobs_tenant_isolation ON scan_jobs
    USING (tenant_id = current_tenant_id())
    WITH CHECK (tenant_id = current_tenant_id());

-- =============================================================================
-- TRIGGERS: auto-update updated_at
-- =============================================================================

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS tenants_updated_at ON tenants;
CREATE TRIGGER tenants_updated_at
    BEFORE UPDATE ON tenants
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS users_updated_at ON users;
CREATE TRIGGER users_updated_at
    BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- =============================================================================
-- COMMENTS (documentation inline)
-- =============================================================================

COMMENT ON TABLE tenants IS 'Top-level tenant registry. One row per customer organization.';
COMMENT ON TABLE users IS 'Platform users. Always scoped to a tenant. MFA is mandatory.';
COMMENT ON TABLE scan_scopes IS 'Authorized scan targets. Domain ownership must be cryptographically verified.';
COMMENT ON TABLE m365_credentials IS 'KMS-encrypted M365 refresh tokens. Never store plaintext.';
COMMENT ON TABLE audit_trail IS 'Immutable action log. RLS + update/delete rules prevent tampering.';
COMMENT ON TABLE scan_jobs IS 'Tracks execution state of all scan pipelines.';
