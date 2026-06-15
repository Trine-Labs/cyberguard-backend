import logging
import httpx
from typing import List, Dict, Any

import asyncio
from app.config import get_settings

logger = logging.getLogger(__name__)

# Global in-memory cache to prevent redundant NVD API lookups across multiple hosts
_GLOBAL_CVE_CACHE = {}

class CveLookupService:
    """
    Looks up CVEs for a given technology and version using the NVD API.
    """
    
    def __init__(self):
        self.client = httpx.AsyncClient(timeout=15.0)
        self.base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        self.api_key = get_settings().nvd_api_key

    async def get_cves_for_tech(self, name: str, version: str) -> List[Dict[str, Any]]:
        """
        Query NVD API via CPE or keyword search.
        """
        tech_key = f"{name.lower()}:{version}"
        
        # Fast path: Serve from cache if available to prevent 6s sleep penalties
        if tech_key in _GLOBAL_CVE_CACHE:
            return _GLOBAL_CVE_CACHE[tech_key]
            
        cves = []
        
        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key
            
        try:
            # Sleep slightly to respect rate limits (50 reqs/30s with key, 5/30s without)
            await asyncio.sleep(0.65 if self.api_key else 6.1)
            
            # Construct a keywordSearch for better fuzzing
            safe_name = name.replace("-", " ")
            params = {"keywordSearch": safe_name, "resultsPerPage": 3}
                
            resp = await self.client.get(self.base_url, params=params, headers=headers)
            
            if resp.status_code == 200:
                data = resp.json()
                for vuln in data.get("vulnerabilities", [])[:5]: # Cap at 5 for performance
                    cve = vuln.get("cve", {})
                    cve_id = cve.get("id")
                    
                    # Extract description
                    descriptions = cve.get("descriptions", [])
                    desc = descriptions[0].get("value", "") if descriptions else "No description"
                    
                    metrics = cve.get("metrics", {})
                    cvss_data = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", [{}]))
                    if cvss_data:
                        cvss_data = cvss_data[0].get("cvssData", {})
                    else:
                        cvss_data = {}
                        
                    score = cvss_data.get("baseScore", 5.0)
                    severity = cvss_data.get("baseSeverity", "medium").lower()
                    cves.append({
                        "cve_id": cve_id,
                        "cvss_score": score,
                        "severity": severity,
                        "description": desc
                    })
            else:
                logger.warning(f"NVD API returned {resp.status_code} for {tech_key}: {resp.text}")
        except Exception as e:
            logger.warning(f"CVE lookup failed for {tech_key}: {e}")
            
        _GLOBAL_CVE_CACHE[tech_key] = cves
        return cves

    async def close(self):
        await self.client.aclose()
