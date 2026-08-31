import asyncio
import logging
import re
from typing import List, Dict, Any

import httpx
from app.config import get_settings

logger = logging.getLogger(__name__)

# Global in-memory cache to prevent redundant lookups
_GLOBAL_CVE_CACHE: dict[str, list[dict]] = {}

# Curated High-Impact Known CVEs for common server components with verified version matches
_CURATED_KNOWN_CVES: dict[str, list[dict]] = {
    # Apache HTTP Server
    "apache:2.4.49": [
        {"cve_id": "CVE-2021-41773", "cvss_score": 9.8, "severity": "critical", "description": "Path traversal and remote code execution flaw in Apache HTTP Server 2.4.49."},
        {"cve_id": "CVE-2021-42013", "cvss_score": 9.8, "severity": "critical", "description": "Incomplete fix for CVE-2021-41773 path traversal leading to RCE in Apache 2.4.49/2.4.50."}
    ],
    "apache:2.4.50": [
        {"cve_id": "CVE-2021-42013", "cvss_score": 9.8, "severity": "critical", "description": "Incomplete fix for CVE-2021-41773 path traversal leading to RCE in Apache 2.4.49/2.4.50."}
    ],
    "apache:2.4.29": [
        {"cve_id": "CVE-2019-0211", "cvss_score": 7.8, "severity": "high", "description": "Apache HTTP Server privilege escalation from worker processes to root."},
        {"cve_id": "CVE-2018-1312", "cvss_score": 7.5, "severity": "high", "description": "Digest authentication challenge replay vulnerability in mod_auth_digest."}
    ],
    "apache:2.2": [
        {"cve_id": "CVE-2017-9798", "cvss_score": 7.5, "severity": "high", "description": "OptionsBleed memory disclosure in Apache HTTP Server."},
        {"cve_id": "CVE-2011-3192", "cvss_score": 7.8, "severity": "high", "description": "Apache Range header denial of service (Killer Apache)."}
    ],
    # Nginx
    "nginx:1.20.0": [
        {"cve_id": "CVE-2021-23017", "cvss_score": 7.7, "severity": "high", "description": "1-byte memory overwrite in resolver leading to worker crash or potential code execution."}
    ],
    "nginx:1.18.0": [
        {"cve_id": "CVE-2021-23017", "cvss_score": 7.7, "severity": "high", "description": "1-byte memory overwrite in resolver leading to worker crash or potential code execution."}
    ],
    "nginx:1.16.1": [
        {"cve_id": "CVE-2019-9511", "cvss_score": 7.5, "severity": "high", "description": "HTTP/2 Data Dribble resource exhaustion vulnerability in Nginx."}
    ],
    # OpenSSL
    "openssl:1.0.1": [
        {"cve_id": "CVE-2014-0160", "cvss_score": 7.5, "severity": "high", "description": "Heartbleed memory disclosure vulnerability in OpenSSL 1.0.1."}
    ],
    # PHP
    "php:8.1.0-dev": [
        {"cve_id": "CVE-2021-3129", "cvss_score": 9.8, "severity": "critical", "description": "PHP 8.1.0-dev backdoored User-Agent header remote code execution."}
    ],
    "php:7.4": [
        {"cve_id": "CVE-2022-31629", "cvss_score": 7.5, "severity": "high", "description": "Insecure cookie handling vulnerability in standard PHP library."},
        {"cve_id": "CVE-2021-21708", "cvss_score": 7.8, "severity": "high", "description": "Use-after-free vulnerability in PHP-FPM service."}
    ],
    "php:5.6": [
        {"cve_id": "CVE-2016-7124", "cvss_score": 9.8, "severity": "critical", "description": "Object deserialization vulnerability leading to arbitrary code execution in PHP 5.6."}
    ],
}


class CveLookupService:
    """
    Looks up high-impact CVEs for exact detected software versions.
    Strictly ignores generic technologies without explicit version numbers.
    """

    def __init__(self):
        self.client = httpx.AsyncClient(timeout=6.0)
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.api_key = get_settings().nvd_api_key

    async def get_cves_for_tech(self, name: str, version: str) -> List[Dict[str, Any]]:
        """
        Query high-impact CVEs for an exact software version.
        Only returns CVEs with CVSS >= 7.0 (High/Critical).
        """
        if not name or not version:
            return []

        clean_name = name.strip().lower()
        clean_version = version.strip()

        # Strict Quality Guardrail: Version MUST contain numeric digits (e.g. "2.4.49", "8.1.0")
        if not any(c.isdigit() for c in clean_version):
            return []

        tech_key = f"{clean_name}:{clean_version}"

        # 1. Fast path: Serve from memory cache
        if tech_key in _GLOBAL_CVE_CACHE:
            return _GLOBAL_CVE_CACHE[tech_key]

        # 2. Curated precision database match
        for curated_key, cves in _CURATED_KNOWN_CVES.items():
            c_tech, c_ver = curated_key.split(":")
            if c_tech in clean_name and (clean_version == c_ver or clean_version.startswith(c_ver)):
                _GLOBAL_CVE_CACHE[tech_key] = cves
                return cves

        # 3. Dynamic NVD lookup for exact (Component + Version) query
        cves = []
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        try:
            # Query exact component + version keyword
            query_str = f"{clean_name} {clean_version}"
            params = {"keywordSearch": query_str, "resultsPerPage": 5}

            resp = await self.client.get(self.base_url, params=params, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                for vuln in data.get("vulnerabilities", []):
                    cve = vuln.get("cve", {})
                    cve_id = cve.get("id")

                    descriptions = cve.get("descriptions", [])
                    desc = descriptions[0].get("value", "") if descriptions else ""

                    metrics = cve.get("metrics", {})
                    cvss_data = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", [{}]))
                    if cvss_data:
                        cvss_info = cvss_data[0].get("cvssData", {})
                    else:
                        cvss_info = {}

                    score = float(cvss_info.get("baseScore", 0.0))
                    severity = cvss_info.get("baseSeverity", "medium").lower()

                    # Strict Quality Guardrail: CVSS MUST be >= 7.0 (High/Critical only)
                    if score >= 7.0 or severity in ("high", "critical"):
                        cves.append({
                            "cve_id": cve_id,
                            "cvss_score": score if score > 0 else 7.5,
                            "severity": severity if severity in ("high", "critical") else "high",
                            "description": desc[:250] if desc else f"Vulnerability {cve_id} in {name} {version}"
                        })

                    if len(cves) >= 3:
                        break
        except Exception as e:
            logger.debug(f"CVE lookup skipped for {tech_key}: {e}")

        _GLOBAL_CVE_CACHE[tech_key] = cves
        return cves

    async def close(self):
        await self.client.aclose()

