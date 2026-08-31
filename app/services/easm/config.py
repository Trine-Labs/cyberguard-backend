"""
EASM Scanner Configuration & Shared Resources
"""
import asyncio
import ipaddress
import json
import logging
import os
import re

import httpx

logger = logging.getLogger(__name__)

# ── Concurrency guards ─────────────────────────────────────────────────────────
# Total number of hosts scanned concurrently across ALL tenants.
_GLOBAL_SCAN_SEM = asyncio.Semaphore(10)

# Tracks tenant locks to queue background scans sequentially.
# Prevents duplicate scans overlapping, but allows them to queue.
_TENANT_LOCKS: dict[str, asyncio.Lock] = {}


def _get_tenant_lock(tenant_id: str) -> asyncio.Lock:
    if tenant_id not in _TENANT_LOCKS:
        _TENANT_LOCKS[tenant_id] = asyncio.Lock()
    return _TENANT_LOCKS[tenant_id]


# ── Shared HTTP client ─────────────────────────────────────────────────────────
# Re-used across all probe functions. Configured for high-throughput VPS infrastructure.
_HTTP_CLIENT = httpx.AsyncClient(
    follow_redirects=True,
    timeout=10.0,
    verify=False,
    limits=httpx.Limits(
        max_connections=200,           # High cap for VPS server
        max_keepalive_connections=50,  # Keep warm connections ready
        keepalive_expiry=15,           # Hold connections for 15s
    ),
    headers={"User-Agent": "CyberGuard-EASM/1.0"},
)

# ── Port scan targets ──────────────────────────────────────────────────────────
COMMON_PORTS = [
    (21,    "FTP",          "high"),
    (22,    "SSH",          "medium"),
    (23,    "Telnet",       "critical"),
    (25,    "SMTP",         "medium"),
    (80,    "HTTP",         "info"),
    (443,   "HTTPS",        "info"),
    (445,   "SMB",          "critical"),
    (1433,  "MSSQL",        "critical"),
    (2082,  "cPanel-HTTP",  "high"),
    (2083,  "cPanel-HTTPS", "high"),
    (2086,  "WHM-HTTP",     "critical"),
    (2087,  "WHM-HTTPS",    "critical"),
    (2095,  "Webmail-HTTP", "medium"),
    (2096,  "Webmail-HTTPS","medium"),
    (3000,  "HTTP-Alt",     "medium"),
    (3003,  "HTTP-Alt",     "medium"),
    (3004,  "HTTP-Alt",     "medium"),
    (3306,  "MySQL",        "critical"),
    (3389,  "RDP",          "critical"),
    (4000,  "HTTP-Alt",     "medium"),
    (5432,  "PostgreSQL",   "critical"),
    (5900,  "VNC",          "critical"),
    (6379,  "Redis",        "critical"),
    (8000,  "HTTP-Alt",     "medium"),
    (8080,  "HTTP-Alt",     "medium"),
    (8081,  "HTTP-Alt",     "medium"),
    (8443,  "HTTPS-Alt",    "low"),
    (8888,  "HTTP-Alt",     "medium"),
    (9090,  "HTTP-Alt",     "medium"),
    (9200,  "Elasticsearch","critical"),
    (10000, "Webmin",       "critical"),
    (27017, "MongoDB",      "critical"),
]

# Ports that are risky when publicly internet-reachable
RISKY_PORTS = {3306, 5432, 6379, 27017, 23, 21, 3389, 445, 9200, 5900, 1433, 2086, 2087, 10000}
# Ports risky only if no auth banner found
CONDITIONALLY_RISKY = {22, 25}

HEADER_WEIGHTS = {
    "content-security-policy": 30,
    "strict-transport-security": 25,
    "x-frame-options": 15,
    "x-content-type-options": 15,
    "referrer-policy": 10,
    "permissions-policy": 5,
}

# Load Signatures Dynamically
_SIGNATURES_FILE = os.path.join(os.path.dirname(__file__), "..", "..", "data", "easm_signatures.json")
try:
    with open(_SIGNATURES_FILE, "r") as f:
        _sigs = json.load(f)
        SENSITIVE_PATH_SIGNATURES = _sigs.get("sensitive_paths", [])
        SUSPICIOUS_PATTERNS = []
        for p in _sigs.get("suspicious_patterns", []):
            SUSPICIOUS_PATTERNS.append({
                "regex": re.compile(p["regex"], re.IGNORECASE),
                "severity": p["severity"],
                "type": p["type"]
            })
        FINGERPRINTS = []
        for fp in _sigs.get("fingerprints", []):
            FINGERPRINTS.append({
                "regex": re.compile(fp["regex"], re.IGNORECASE),
                "app": fp["app"],
                "severity": fp["severity"],
                "type": fp["type"]
            })
except Exception as e:
    logger.error(f"Failed to load signatures: {e}")
    SENSITIVE_PATH_SIGNATURES = []
    SUSPICIOUS_PATTERNS = []
    FINGERPRINTS = []


def _is_cidr(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        return False


def _is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False
