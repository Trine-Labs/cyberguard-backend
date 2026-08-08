"""
EASM Scanner Subdomain Enumeration Module (Passive & Active)
"""
import asyncio
import os
import uuid

import dns.asyncresolver

from app.services.easm.config import _HTTP_CLIENT, logger


async def _enumerate_subdomains(root_domain: str) -> list[str]:
    """
    Passively and actively aggregate subdomains:
      1. crt.sh — Certificate Transparency log search
      2. HackerTarget — Passive DNS / IP lookup
      3. Active Brute-forcing — dnspython resolver
    Returns a deduplicated list of subdomains (not including the root itself).
    """
    subdomains: set[str] = set()

    results = await asyncio.gather(
        _crtsh_subdomains(root_domain),
        _hackertarget_subdomains(root_domain),
        _active_subdomain_bruteforce(root_domain),
        return_exceptions=True,
    )

    for result in results:
        if isinstance(result, Exception):
            logger.debug(f"[EASM] Subdomain source error for {root_domain}: {result}")
            continue
        subdomains.update(result)

    # Filter: must end with .root_domain and not contain wildcards
    clean = set()
    for sub in subdomains:
        sub = sub.strip().lower().lstrip("*.")
        if sub and (sub.endswith(f".{root_domain}") or sub == root_domain):
            if "*" not in sub:
                clean.add(sub)

    # Remove the root itself — caller adds it
    clean.discard(root_domain)
    logger.info(f"[EASM] crt.sh+HackerTarget found {len(clean)} unique subdomains for {root_domain}")
    return sorted(clean)


async def _check_wildcard_dns(domain: str, resolver: dns.asyncresolver.Resolver) -> bool:
    """Check if the domain has a wildcard DNS record by querying a random non-existent subdomain."""
    random_sub = f"wildcard-test-{uuid.uuid4().hex[:8]}.{domain}"
    try:
        await resolver.resolve(random_sub, 'A')
        return True
    except Exception:
        return False


async def _active_subdomain_bruteforce(root_domain: str) -> list[str]:
    """
    Actively brute-force subdomains using dnspython and a wordlist.
    """
    subdomains: set[str] = set()
    wordlist_path = os.path.join(os.path.dirname(__file__), "..", "..", "data", "subdomains_wordlist.txt")

    if not os.path.exists(wordlist_path):
        logger.warning(f"[EASM] Wordlist not found at {wordlist_path}")
        return []

    try:
        with open(wordlist_path, "r") as f:
            words = [line.strip().lower() for line in f if line.strip()]
    except Exception as e:
        logger.error(f"[EASM] Error reading wordlist: {e}")
        return []

    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 1.5
    resolver.lifetime = 1.5

    # Check for wildcard DNS first
    has_wildcard = await _check_wildcard_dns(root_domain, resolver)
    if has_wildcard:
        logger.info(f"[EASM] Wildcard DNS detected for {root_domain}. Skipping brute-force to avoid false positives.")
        return []

    logger.info(f"[EASM] Starting active brute-force for {root_domain} with {len(words)} words...")

    sem = asyncio.Semaphore(200)

    async def check_sub(word: str):
        sub = f"{word}.{root_domain}"
        async with sem:
            try:
                await resolver.resolve(sub, 'A')
                return sub
            except Exception:
                return None

    tasks = [asyncio.create_task(check_sub(w)) for w in words]
    results = await asyncio.gather(*tasks, return_exceptions=True)

    for res in results:
        if isinstance(res, str):
            subdomains.add(res)

    logger.info(f"[EASM] Active brute-force found {len(subdomains)} subdomains for {root_domain}")
    return list(subdomains)


async def _crtsh_subdomains(domain: str) -> list[str]:
    """
    Query crt.sh Certificate Transparency logs for subdomains.
    Returns list of unique names from matching certificates.
    """
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    subdomains: set[str] = set()
    try:
        resp = await _HTTP_CLIENT.get(url)
        if resp.status_code == 200:
            entries = resp.json()
            for entry in entries:
                name = entry.get("name_value", "")
                for line in name.split("\n"):
                    line = line.strip().lower().lstrip("*.")
                    if line:
                        subdomains.add(line)
    except Exception as e:
        logger.debug(f"[EASM] crt.sh error for {domain}: {e}")
    return list(subdomains)


async def _hackertarget_subdomains(domain: str) -> list[str]:
    """
    Query HackerTarget passive DNS for subdomains.
    Returns list of unique hostnames.
    """
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    subdomains: set[str] = set()
    try:
        resp = await _HTTP_CLIENT.get(url)
        if resp.status_code == 200:
            for line in resp.text.splitlines():
                parts = line.split(",")
                if parts:
                    host = parts[0].strip().lower()
                    if host and "error" not in host and "api count" not in host:
                        subdomains.add(host)
    except Exception as e:
        logger.debug(f"[EASM] HackerTarget error for {domain}: {e}")
    return list(subdomains)
