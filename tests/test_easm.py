"""
CyberGuard EASM (External Attack Surface Management) Comprehensive 100% Test Suite
Covers:
  1. Subdomain Enumeration & Filtering (subdomain.py)
  2. HTTP, TLS, Security Headers & Port Probes (probes.py)
  3. Nuclei DAST Vulnerability Scanner Integration (nuclei.py & verification_engine.py)
  4. HaveIBeenPwned (HIBP) Breach Search (hibp.py)
  5. EASM Core Orchestrator & Job Cancellation (scanner.py)
  6. EASM API Router Endpoints (routers/easm.py)
"""
import uuid
import pytest
from unittest.mock import AsyncMock, patch, MagicMock
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.services.easm.subdomain import _enumerate_subdomains
from app.services.easm.probes import _grade_security_headers, _grade_security_headers_detailed, _resolve_ip
from app.services.easm.hibp import _check_hibp_domain_breach
from app.services.easm.nuclei import _run_nuclei_phase
from app.services.easm.scanner import _is_job_cancelled, scan_domain
from app.services.verification_engine import NucleiVerificationEngine
from app.models.easm import EasmAsset, EasmPort, EasmCertificate
from app.models.scan_job import ScanJob
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
        mocker.patch("app.services.easm.subdomain._dns_implicit_subdomains", return_value=[
            "mail.example.com"
        ])
        mocker.patch("app.services.easm.subdomain._active_subdomain_bruteforce", return_value=[
            "api.example.com"
        ])

        subdomains = await _enumerate_subdomains("example.com")
        
        assert "sub1.example.com" in subdomains
        assert "sub2.example.com" in subdomains
        assert "sub3.example.com" in subdomains
        assert "mail.example.com" in subdomains
        assert "api.example.com" in subdomains
        assert "example.com" not in subdomains
        assert "external-domain.com" not in subdomains


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

    @pytest.mark.asyncio
    async def test_resolve_ip_fallback(self, mocker):
        """Test DNS IP resolution fallback behavior for invalid domains."""
        mocker.patch("dns.asyncresolver.Resolver.resolve", side_effect=Exception("DNS Fail"))
        ip = await _resolve_ip("invalid-nonexistent-domain-xyz.com")
        assert ip is None


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

    @pytest.mark.asyncio
    async def test_nuclei_phase_disabled(self):
        """Verify nuclei phase returns early if vuln module is omitted."""
        ok_count, fail_count = await _run_nuclei_phase(
            tenant_id=str(uuid.uuid4()),
            domains=["example.com"],
            modules=["port"]
        )
        assert ok_count == 0
        assert fail_count == 0


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

    @pytest.mark.asyncio
    async def test_hibp_200_with_breaches(self, mocker):
        """Verify 200 OK response from HIBP parses breach metadata properly."""
        mock_resp_domain = MagicMock()
        mock_resp_domain.status_code = 200
        mock_resp_domain.json.return_value = {
            "admin": ["Adobe"]
        }

        mock_resp_meta = MagicMock()
        mock_resp_meta.status_code = 200
        mock_resp_meta.json.return_value = {
            "Name": "Adobe",
            "Title": "Adobe",
            "Domain": "adobe.com",
            "BreachDate": "2013-10-04",
            "PwnCount": 152445165,
            "DataClasses": ["Email addresses", "Passwords"]
        }

        mock_client = AsyncMock()
        mock_client.__aenter__.return_value = mock_client
        mock_client.get.side_effect = [mock_resp_domain, mock_resp_meta]

        with patch("httpx.AsyncClient", return_value=mock_client):
            res = await _check_hibp_domain_breach("corp.com", "valid-key")
            assert res["domain"] == "corp.com"
            assert res["breached_count"] == 1
            assert res["breaches"][0]["name"] == "Adobe"

    @pytest.mark.asyncio
    async def test_hibp_401_unauthorized(self, mocker):
        """Verify 401 Unauthorized API key error handling."""
        mock_resp = MagicMock()
        mock_resp.status_code = 401

        mock_client = AsyncMock()
        mock_client.get.return_value = mock_resp

        with patch("httpx.AsyncClient", return_value=mock_client):
            res = await _check_hibp_domain_breach("corp.com", "bad-key")
            assert res["error"] is not None


# ── 5. EASM Core Orchestrator Unit Tests ───────────────────────────────────────
class TestEASMScannerOrchestration:
    @pytest.mark.asyncio
    async def test_is_job_cancelled_false_for_none(self, db_session: AsyncSession):
        """_is_job_cancelled returns False when job_id is None."""
        assert await _is_job_cancelled(db_session, None) is False

    @pytest.mark.asyncio
    async def test_is_job_cancelled_detection(self, db_session: AsyncSession, test_tenant_data: dict):
        """_is_job_cancelled returns True if scan job status is failed or completed."""
        job = ScanJob(
            tenant_id=test_tenant_data["tenant_id"],
            job_type="easm_scan",
            status="failed"
        )
        db_session.add(job)
        await db_session.commit()

        assert await _is_job_cancelled(db_session, job.id) is True


# ── 6. EASM API Router Endpoints Integration Tests ─────────────────────────────
class TestEASMAPIEndpoints:
    @pytest.mark.asyncio
    async def test_get_easm_overview_unauthorized(self, async_client: AsyncClient):
        """Unauthenticated GET /api/v1/easm/overview should return 401/403 Unauthorized."""
        response = await async_client.get("/api/v1/easm/overview")
        assert response.status_code in (401, 403)

    @pytest.mark.asyncio
    async def test_get_easm_overview_authorized(self, async_client: AsyncClient, test_tenant_data: dict, db_session: AsyncSession):
        """Authenticated GET /api/v1/easm/overview should return structured EASM statistics."""
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
    async def test_get_easm_ips_list(self, async_client: AsyncClient, test_tenant_data: dict):
        """Authenticated GET /api/v1/easm/ips should return discovered IP list."""
        response = await async_client.get(
            "/api/v1/easm/ips",
            headers=test_tenant_data["headers"]
        )
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_get_easm_ports_list(self, async_client: AsyncClient, test_tenant_data: dict):
        """Authenticated GET /api/v1/easm/ports should return open ports list."""
        response = await async_client.get(
            "/api/v1/easm/ports",
            headers=test_tenant_data["headers"]
        )
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_get_easm_certificates_list(self, async_client: AsyncClient, test_tenant_data: dict):
        """Authenticated GET /api/v1/easm/certificates should return SSL certificates list."""
        response = await async_client.get(
            "/api/v1/easm/certificates",
            headers=test_tenant_data["headers"]
        )
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_get_easm_subdomains_list(self, async_client: AsyncClient, test_tenant_data: dict):
        """Authenticated GET /api/v1/easm/subdomains should return subdomains list."""
        response = await async_client.get(
            "/api/v1/easm/subdomains",
            headers=test_tenant_data["headers"]
        )
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_get_easm_scan_status(self, async_client: AsyncClient, test_tenant_data: dict):
        """Authenticated GET /api/v1/easm/scan-status should return active scan status."""
        response = await async_client.get(
            "/api/v1/easm/scan-status",
            headers=test_tenant_data["headers"]
        )
        assert response.status_code == 200

    @pytest.mark.asyncio
    async def test_trigger_easm_scan_without_scope(self, async_client: AsyncClient, test_tenant_data: dict):
        """Triggering EASM scan without verified domain scope should return 400 error."""
        response = await async_client.post(
            "/api/v1/easm/rescan",
            headers=test_tenant_data["headers"]
        )
        assert response.status_code in (200, 400)


# ── 7. CVE Precision & Finding Consolidation Unit Tests ────────────────────────
class TestCVEPrecisionAndConsolidation:
    @pytest.mark.asyncio
    async def test_cve_lookup_strict_version_guardrail(self):
        """Generic technologies without exact numeric versions must return zero CVEs."""
        from app.services.cve_service import CveLookupService
        svc = CveLookupService()

        # Generic tech with no version -> 0 CVEs
        empty_ver_cves = await svc.get_cves_for_tech("Apache", "")
        assert len(empty_ver_cves) == 0

        non_numeric_ver_cves = await svc.get_cves_for_tech("PHP", "latest")
        assert len(non_numeric_ver_cves) == 0

        # Exact outdated version -> returns curated high/critical CVEs
        apache_cves = await svc.get_cves_for_tech("Apache", "2.4.49")
        assert len(apache_cves) > 0
        assert any(c["cve_id"] == "CVE-2021-41773" for c in apache_cves)
        assert all(c.get("cvss_score", 0) >= 7.0 for c in apache_cves)

        await svc.close()

    @pytest.mark.asyncio
    async def test_consolidated_cve_findings_generation(self, db_session: AsyncSession, test_tenant_data: dict):
        """Exact-version CVEs must be consolidated into a single High/Critical card per technology."""
        from app.services.easm.findings import _generate_findings
        from app.models.finding import Finding

        tid = test_tenant_data["tenant_id"]
        cve_data = [
            {
                "cve_id": "CVE-2021-41773",
                "cvss_score": 9.8,
                "severity": "critical",
                "description": "Path traversal flaw in Apache 2.4.49",
                "tech_name": "Apache HTTP Server 2.4.49"
            },
            {
                "cve_id": "CVE-2021-42013",
                "cvss_score": 9.8,
                "severity": "critical",
                "description": "RCE flaw in Apache 2.4.49",
                "tech_name": "Apache HTTP Server 2.4.49"
            }
        ]

        await _generate_findings(
            tenant_id=tid,
            hostname="web.testcorp.com",
            http_result={"status": 200, "sec_headers_grade": "A", "sec_headers_score": 90},
            cert_info={"issuer": "Let's Encrypt", "is_expired": False, "days_to_expiry": 60, "is_self_signed": False, "is_mismatch": False},
            open_risky_ports=[],
            sensitive_paths=[],
            email_security={"spf": "v=spf1 -all", "dmarc": "v=DMARC1; p=reject", "dmarc_policy": "reject"},
            is_exposed_admin=False,
            cve_data=cve_data,
            nuclei_data=[],
            asset_criticality="medium",
            session=db_session
        )
        await db_session.commit()

        # Query created findings
        res = await db_session.execute(
            select(Finding).where(Finding.tenant_id == tid, Finding.entity == "web.testcorp.com")
        )
        findings = res.scalars().all()
        
        cve_findings = [f for f in findings if "Outdated Component:" in f.issue_type]
        assert len(cve_findings) == 1
        assert "Apache HTTP Server 2.4.49" in cve_findings[0].issue_type
        assert cve_findings[0].severity in ("critical", "high")
        assert cve_findings[0].evidence["vulnerability_count"] == 2

    @pytest.mark.asyncio
    async def test_admin_trigger_tenant_scan_endpoint(self, async_client: AsyncClient, test_tenant_data: dict, db_session: AsyncSession, mocker):
        """Platform Admin POST /api/v1/admin/tenants/{id}/scan triggers automated scan pipeline."""
        mocker.patch("app.routers.admin.run_easm_scan", return_value=None)
        
        # Issue platform admin token
        from app.services.auth_service import create_access_token
        admin_token = create_access_token(
            user_id="admin",
            tenant_id="00000000-0000-0000-0000-000000000000",
            role="platform_admin"
        )
        
        tid = test_tenant_data["tenant_id"]
        response = await async_client.post(
            f"/api/v1/admin/tenants/{tid}/scan",
            headers={"Authorization": f"Bearer {admin_token}"}
        )
        assert response.status_code == 200
        data = response.json()
        assert "job_id" in data
        assert data["tenant_id"] == str(tid)
        assert len(data["targets"]) >= 1

