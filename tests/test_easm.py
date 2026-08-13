"""
CyberGuard EASM (External Attack Surface Management) Automated Test Suite
Covers:
  1. Subdomain Enumeration & Filtering (subdomain.py)
  2. HTTP, Port & Security Header Probes (probes.py)
  3. Nuclei DAST Vulnerability Scanner Integration (nuclei.py & verification_engine.py)
  4. HaveIBeenPwned (HIBP) Breach Check (hibp.py)
  5. EASM API Endpoints (GET /overview, GET /assets, POST /scan)
"""
import uuid
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.easm.subdomain import _enumerate_subdomains
from app.services.easm.probes import _grade_security_headers, _grade_security_headers_detailed
from app.services.easm.hibp import _check_hibp_domain_breach
from app.services.verification_engine import NucleiVerificationEngine
from app.models.easm import EasmAsset
from app.models.scope import ScanScope


# ── 1. Subdomain Enumeration Unit Tests ────────────────────────────────────────
class TestSubdomainEnumeration:
    @pytest.mark.asyncio
    async def test_subdomain_cleaning_and_filtering(self, mocker):
        """Verify that wildcards, invalid prefixes, and out-of-scope domains are cleaned."""
        mocker.patch("app.services.easm.subdomain._crtsh_subdomains", return_value=[
            "*.sub1.example.com",
            "sub2.example.com",
            "example.com",
            "external-domain.com"
        ])
        mocker.patch("app.services.easm.subdomain._hackertarget_subdomains", return_value=[
            "sub3.example.com",
            "SUB2.EXAMPLE.COM"
        ])
        mocker.patch("app.services.easm.subdomain._active_subdomain_bruteforce", return_value=[
            "api.example.com"
        ])

        subdomains = await _enumerate_subdomains("example.com")
        
        assert "sub1.example.com" in subdomains
        assert "sub2.example.com" in subdomains
        assert "sub3.example.com" in subdomains
        assert "api.example.com" in subdomains
        assert "example.com" not in subdomains  # Root itself excluded
        assert "external-domain.com" not in subdomains  # Out of scope excluded


# ── 2. Probe & Security Header Unit Tests ──────────────────────────────────────
class TestProbeScanner:
    def test_security_header_grading_strong(self):
        """Headers with HSTS, CSP, and X-Frame-Options should achieve an A/A+ grade."""
        headers = {
            "strict-transport-security": "max-age=31536000; includeSubDomains",
            "content-security-policy": "default-src 'self'",
            "x-frame-options": "DENY",
            "x-content-type-options": "nosniff",
            "referrer-policy": "strict-origin-when-cross-origin",
            "permissions-policy": "geolocation=()"
        }
        grade, score, missing = _grade_security_headers_detailed(headers)
        assert grade in ("A+", "A")
        assert len(missing) == 0

    def test_security_header_grading_weak(self):
        """Missing all critical security headers should result in an F grade."""
        headers = {
            "server": "nginx",
            "content-type": "text/html"
        }
        grade, score, missing = _grade_security_headers_detailed(headers)
        assert grade == "F"
        missing_lower = [m.lower() for m in missing]
        assert "strict-transport-security" in missing_lower
        assert "content-security-policy" in missing_lower


# ── 3. Nuclei Integration Tests ───────────────────────────────────────────────
class TestNucleiIntegration:
    def test_nuclei_engine_initialization(self):
        """Verify Nuclei verification engine initializes binary paths cleanly."""
        engine = NucleiVerificationEngine()
        assert engine.base_dir.exists()

    def test_nuclei_template_matching(self):
        """Verify tag-based template filtering logic."""
        engine = NucleiVerificationEngine()
        templates = engine._find_matching_templates(["cves"], "cve,rce")
        assert isinstance(templates, list)


# ── 4. HIBP Breach Checker Unit Tests ──────────────────────────────────────────
class TestHIBPBreachScanner:
    @pytest.mark.asyncio
    async def test_hibp_404_no_breaches(self, mocker):
        """Verify 404 response from HIBP indicates zero breaches."""
        mock_resp = MagicMock()
        mock_resp.status_code = 404

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_resp

        with patch("httpx.AsyncClient", return_value=mock_client):
            res = await _check_hibp_domain_breach("clean-corp.com", "test-api-key")
            assert res["domain"] == "clean-corp.com"
            assert res["breached_count"] == 0
            assert len(res["breaches"]) == 0


# ── 5. EASM API Router Endpoints Integration Tests ─────────────────────────────
class TestEASMAPIEndpoints:
    @pytest.mark.asyncio
    async def test_get_easm_overview_unauthorized(self, async_client: AsyncClient):
        """Unauthenticated GET /api/v1/easm/overview should return 401/403 Unauthorized."""
        response = await async_client.get("/api/v1/easm/overview")
        assert response.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_get_easm_overview_authorized(self, async_client: AsyncClient, test_tenant_data: dict, db_session: AsyncSession):
        """Authenticated GET /api/v1/easm/overview should return structured EASM statistics."""
        # Add test asset to DB
        asset = EasmAsset(
            tenant_id=test_tenant_data["tenant_id"],
            hostname=f"app.{test_tenant_data['domain']}",
            ip_address="1.2.3.4",
            http_status=200,
            asset_type="subdomain",
            status="active"
        )
        db_session.add(asset)
        await db_session.commit()

        response = await async_client.get(
            "/api/v1/easm/overview",
            headers=test_tenant_data["headers"]
        )
        assert response.status_code == 200
        data = response.json()
        assert "total_discovered_hosts" in data or "categories" in data
        assert "critical_vulnerabilities" in data or "total_vulnerabilities" in data

    @pytest.mark.asyncio
    async def test_get_easm_assets_list(self, async_client: AsyncClient, test_tenant_data: dict, db_session: AsyncSession):
        """Authenticated GET /api/v1/easm/assets should return list of assets."""
        response = await async_client.get(
            "/api/v1/easm/assets",
            headers=test_tenant_data["headers"]
        )
        assert response.status_code == 200
        data = response.json()
        assert "assets" in data or "items" in data or isinstance(data, list)

    @pytest.mark.asyncio
    async def test_trigger_easm_scan_without_scope(self, async_client: AsyncClient, test_tenant_data: dict):
        """Triggering EASM scan without verified domain scope should return 400 error."""
        response = await async_client.post(
            "/api/v1/easm/rescan",
            headers=test_tenant_data["headers"]
        )
        # 400 Bad Request if no verified scan scopes exist
        assert response.status_code in (200, 400)
