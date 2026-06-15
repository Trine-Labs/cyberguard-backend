-- =============================================================================
-- CyberGuard Database Schema — Phase 2
-- EASM (External Attack Surface Management) + Unified Findings
-- Run this AFTER schema.sql
-- =============================================================================

-- =============================================================================
-- ENUMS
-- =============================================================================

DO $$ BEGIN
  CREATE TYPE asset_status AS ENUM ('active', 'inactive', 'unknown');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TYPE risk_level AS ENUM ('critical', 'high', 'medium', 'low', 'info');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TYPE finding_status AS ENUM ('open', 'resolved', 'accepted_risk', 'false_positive');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TYPE finding_source AS ENUM ('m365', 'ext_scanner', 'manual');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TYPE finding_severity AS ENUM ('critical', 'high', 'medium', 'low', 'info');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

DO $$ BEGIN
  CREATE TYPE sec_headers_grade AS ENUM ('A', 'B', 'C', 'D', 'F', 'unknown');
EXCEPTION WHEN duplicate_object THEN NULL; END $$;

-- =============================================================================
-- TABLE: easm_assets
-- Internet-facing hostnames discovered within authorized scope.
-- =============================================================================

CREATE TABLE IF NOT EXISTS easm_assets (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    hostname            VARCHAR(512) NOT NULL,
    ip_address          INET,
    http_status         INTEGER,                     -- HTTP response code (200, 403, etc.)
    asset_type          VARCHAR(50) DEFAULT 'web',   -- web, api, admin, mail, etc.
    tech_stack          TEXT[] NOT NULL DEFAULT '{}',
    sec_headers_grade   sec_headers_grade NOT NULL DEFAULT 'unknown',
    cve_count           INTEGER NOT NULL DEFAULT 0,
    is_catch_all        BOOLEAN NOT NULL DEFAULT FALSE,
    is_exposed_admin    BOOLEAN NOT NULL DEFAULT FALSE,
    status              asset_status NOT NULL DEFAULT 'active',
    last_seen_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    discovered_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, hostname)
);

CREATE INDEX IF NOT EXISTS idx_easm_assets_tenant_id ON easm_assets(tenant_id);
CREATE INDEX IF NOT EXISTS idx_easm_assets_status ON easm_assets(status);
CREATE INDEX IF NOT EXISTS idx_easm_assets_cve_count ON easm_assets(cve_count DESC);

ALTER TABLE easm_assets ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS easm_assets_tenant_isolation ON easm_assets;
CREATE POLICY easm_assets_tenant_isolation ON easm_assets
    USING (tenant_id = current_tenant_id())
    WITH CHECK (tenant_id = current_tenant_id());

-- =============================================================================
-- TABLE: easm_ports
-- Open ports discovered on scanned IP addresses.
-- =============================================================================

CREATE TABLE IF NOT EXISTS easm_ports (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    asset_id        UUID REFERENCES easm_assets(id) ON DELETE CASCADE,
    ip_address      INET NOT NULL,
    port            INTEGER NOT NULL,
    protocol        VARCHAR(10) NOT NULL DEFAULT 'tcp',  -- tcp, udp
    service         VARCHAR(100),                        -- http, https, ssh, mysql, etc.
    banner          TEXT,                                -- service banner (version info)
    risk_level      risk_level NOT NULL DEFAULT 'info',
    is_risky        BOOLEAN NOT NULL DEFAULT FALSE,      -- unexpected exposure
    discovered_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, ip_address, port, protocol)
);

CREATE INDEX IF NOT EXISTS idx_easm_ports_tenant_id ON easm_ports(tenant_id);
CREATE INDEX IF NOT EXISTS idx_easm_ports_risk_level ON easm_ports(risk_level);
CREATE INDEX IF NOT EXISTS idx_easm_ports_is_risky ON easm_ports(is_risky);

ALTER TABLE easm_ports ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS easm_ports_tenant_isolation ON easm_ports;
CREATE POLICY easm_ports_tenant_isolation ON easm_ports
    USING (tenant_id = current_tenant_id())
    WITH CHECK (tenant_id = current_tenant_id());

-- =============================================================================
-- TABLE: easm_certificates
-- TLS certificates observed on scanned hostnames.
-- =============================================================================

CREATE TABLE IF NOT EXISTS easm_certificates (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    hostname        VARCHAR(512) NOT NULL,
    issuer          VARCHAR(512),
    subject         VARCHAR(512),
    serial_number   VARCHAR(256),
    fingerprint     VARCHAR(128),
    valid_from      TIMESTAMPTZ,
    valid_to        TIMESTAMPTZ,
    is_expired      BOOLEAN NOT NULL DEFAULT FALSE,
    is_self_signed  BOOLEAN NOT NULL DEFAULT FALSE,
    days_to_expiry  INTEGER,                        -- negative = already expired
    sans            TEXT[] NOT NULL DEFAULT '{}',   -- Subject Alternative Names
    discovered_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(tenant_id, hostname, fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_easm_certs_tenant_id ON easm_certificates(tenant_id);
CREATE INDEX IF NOT EXISTS idx_easm_certs_is_expired ON easm_certificates(is_expired);
CREATE INDEX IF NOT EXISTS idx_easm_certs_days_to_expiry ON easm_certificates(days_to_expiry);

ALTER TABLE easm_certificates ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS easm_certs_tenant_isolation ON easm_certificates;
CREATE POLICY easm_certs_tenant_isolation ON easm_certificates
    USING (tenant_id = current_tenant_id())
    WITH CHECK (tenant_id = current_tenant_id());

-- =============================================================================
-- TABLE: findings
-- Unified, deduplicated security findings from all sources (M365 + EASM).
-- Each finding has a stable human-readable ID for audit trail references.
-- =============================================================================

CREATE SEQUENCE IF NOT EXISTS findings_seq START 1042;  -- Start at FIN-1042 for demo realism

CREATE TABLE IF NOT EXISTS findings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    finding_num     INTEGER NOT NULL DEFAULT nextval('findings_seq'),
    severity        finding_severity NOT NULL,
    source          finding_source NOT NULL,
    issue_type      VARCHAR(255) NOT NULL,           -- "PIM Active Admin — No MFA"
    entity          VARCHAR(512) NOT NULL,           -- "breakglass@bank.ma"
    status          finding_status NOT NULL DEFAULT 'open',
    evidence        JSONB NOT NULL DEFAULT '{}',     -- raw evidence blob
    tags            TEXT[] NOT NULL DEFAULT '{}',
    first_seen_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at     TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Generate stable human ID: FIN-1042
CREATE INDEX IF NOT EXISTS idx_findings_tenant_id ON findings(tenant_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_findings_status ON findings(status);
CREATE INDEX IF NOT EXISTS idx_findings_source ON findings(source);
CREATE INDEX IF NOT EXISTS idx_findings_created_at ON findings(created_at DESC);

ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS findings_tenant_isolation ON findings;
CREATE POLICY findings_tenant_isolation ON findings
    USING (tenant_id = current_tenant_id())
    WITH CHECK (tenant_id = current_tenant_id());

-- Auto-update updated_at
DROP TRIGGER IF EXISTS easm_assets_updated_at ON easm_assets;
CREATE TRIGGER easm_assets_updated_at
    BEFORE UPDATE ON easm_assets
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS easm_certs_updated_at ON easm_certificates;
CREATE TRIGGER easm_certs_updated_at
    BEFORE UPDATE ON easm_certificates
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

DROP TRIGGER IF EXISTS findings_updated_at ON findings;
CREATE TRIGGER findings_updated_at
    BEFORE UPDATE ON findings
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- =============================================================================
-- COMMENTS
-- =============================================================================
COMMENT ON TABLE easm_assets IS 'Internet-facing hostnames discovered via passive DNS + active probing within authorized scan scope.';
COMMENT ON TABLE easm_ports IS 'Open ports enumerated on scanned IP space. Risky = unexpected service exposure.';
COMMENT ON TABLE easm_certificates IS 'TLS certificate metadata observed per hostname. Tracks expiry and self-signed issues.';
COMMENT ON TABLE findings IS 'Unified security findings from all sources. Single pane of glass for M365 identity risks + external attack surface exposure.';
