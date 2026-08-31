"""
EASM Scanner Subdomain Enumeration Module (Passive & Active Multi-Source)
"""
import asyncio
import os
import uuid

import dns.asyncresolver

from app.services.easm.config import _HTTP_CLIENT, logger


async def _enumerate_subdomains(root_domain: str) -> list[str]:
    """
    Passively and actively aggregate subdomains from multiple redundant intelligence feeds:
      1. crt.sh — Certificate Transparency log search
      2. Certspotter — Secondary Certificate Transparency API
      3. AlienVault OTX — Open Threat Exchange Passive DNS
      4. Anubis DB — Passive Subdomain Aggregator
      5. HackerTarget — Passive DNS / IP lookup
      6. DNS Records & Implicit MX/NS/SPF/Service Prefixes
      7. Active Multi-Resolver Brute-forcing — dnspython with rotating public nameservers
    Returns a clean, deduplicated list of subdomains (not including the root itself).
    """
    subdomains: set[str] = set()

    results = await asyncio.gather(
        _crtsh_subdomains(root_domain),
        _certspotter_subdomains(root_domain),
        _alienvault_subdomains(root_domain),
        _anubis_subdomains(root_domain),
        _hackertarget_subdomains(root_domain),
        _dns_implicit_subdomains(root_domain),
        _active_subdomain_bruteforce(root_domain),
        return_exceptions=True,
    )

    for result in results:
        if isinstance(result, Exception):
            logger.debug(f"[EASM] Subdomain source error for {root_domain}: {result}")
            continue
        if isinstance(result, (list, set)):
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
    logger.info(f"[EASM] Multi-source subdomain discovery found {len(clean)} unique subdomains for {root_domain}")
    return sorted(clean)


def _get_configured_resolver() -> dns.asyncresolver.Resolver:
    """Create an asynchronous DNS resolver configured with redundant high-speed public nameservers."""
    resolver = dns.asyncresolver.Resolver()
    resolver.nameservers = [
        '1.1.1.1',  # Cloudflare Primary
        '8.8.8.8',  # Google Primary
        '9.9.9.9',  # Quad9 Primary
        '1.0.0.1',  # Cloudflare Secondary
        '8.8.4.4',  # Google Secondary
    ]
    resolver.timeout = 2.0
    resolver.lifetime = 2.5
    return resolver


async def _dns_implicit_subdomains(root_domain: str) -> list[str]:
    """
    Discover implicit subdomains from DNS MX, NS, CNAME, SPF records, and core service prefixes.
    """
    found: set[str] = set()
    resolver = _get_configured_resolver()

    # 1. MX Records Discovery (e.g. mail.domain.com, smtp.domain.com)
    try:
        mx_answers = await resolver.resolve(root_domain, 'MX')
        for rdata in mx_answers:
            exchange_host = str(rdata.exchange).rstrip('.').lower()
            if exchange_host.endswith(f".{root_domain}") or exchange_host == root_domain:
                found.add(exchange_host)
    except Exception:
        pass

    # 2. NS Records Discovery (e.g. ns1.domain.com, dns.domain.com)
    try:
        ns_answers = await resolver.resolve(root_domain, 'NS')
        for rdata in ns_answers:
            ns_host = str(rdata.target).rstrip('.').lower()
            if ns_host.endswith(f".{root_domain}") or ns_host == root_domain:
                found.add(ns_host)
    except Exception:
        pass

    # 3. Common Enterprise Service Prefixes (Direct A-record probing)
    common_service_prefixes = [
        "www", "mail", "webmail", "smtp", "pop", "imap", "autodiscover", "autoconfig",
        "vpn", "remote", "portal", "admin", "gateway", "cpanel", "whm", "webdisk",
        "api", "app", "dashboard", "secure", "auth", "sso", "login", "staging",
        "dev", "test", "demo", "status", "shop", "blog", "cloud", "ns1", "ns2",
        "cdn", "static", "assets", "beta", "intranet", "git", "gitlab", "jenkins"
    ]

    has_wildcard = await _check_wildcard_dns(root_domain, resolver)
    if not has_wildcard:
        sem = asyncio.Semaphore(50)

        async def _check_prefix(prefix: str):
            candidate = f"{prefix}.{root_domain}"
            async with sem:
                try:
                    await resolver.resolve(candidate, 'A')
                    return candidate
                except Exception:
                    try:
                        await resolver.resolve(candidate, 'CNAME')
                        return candidate
                    except Exception:
                        return None

        prefix_tasks = [_check_prefix(p) for p in common_service_prefixes]
        prefix_results = await asyncio.gather(*prefix_tasks, return_exceptions=True)
        for r in prefix_results:
            if isinstance(r, str):
                found.add(r)

    # 4. TXT / SPF Record Hostname Extraction
    try:
        txt_answers = await resolver.resolve(root_domain, 'TXT')
        for rdata in txt_answers:
            txt_str = "".join([s.decode('utf-8', errors='ignore') for s in rdata.strings])
            import re
            for match in re.findall(r'(?:include|redirect|ptr|exists):([a-zA-Z0-9_\-\.]+)', txt_str):
                m_host = match.strip().lower().rstrip('.')
                if m_host.endswith(f".{root_domain}"):
                    found.add(m_host)
    except Exception:
        pass

    return list(found)


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
    Actively brute-force subdomains using dnspython and an extensive wordlist with multi-resolver fallback.
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

    resolver = _get_configured_resolver()

    # Check for wildcard DNS first
    has_wildcard = await _check_wildcard_dns(root_domain, resolver)
    if has_wildcard:
        logger.info(f"[EASM] Wildcard DNS detected for {root_domain}. Skipping brute-force to avoid false positives.")
        return []

    logger.info(f"[EASM] Starting active brute-force for {root_domain} with {len(words)} words...")

    sem = asyncio.Semaphore(150)

    async def check_sub(word: str):
        sub = f"{word}.{root_domain}"
        async with sem:
            try:
                await resolver.resolve(sub, 'A')
                return sub
            except Exception:
                try:
                    await resolver.resolve(sub, 'CNAME')
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
    """
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    subdomains: set[str] = set()
    try:
        resp = await _HTTP_CLIENT.get(url, timeout=10.0)
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


async def _certspotter_subdomains(domain: str) -> list[str]:
    """
    Query Certspotter Certificate Transparency API for subdomains (secondary CT feed).
    """
    url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
    subdomains: set[str] = set()
    try:
        resp = await _HTTP_CLIENT.get(url, timeout=8.0)
        if resp.status_code == 200:
            entries = resp.json()
            if isinstance(entries, list):
                for entry in entries:
                    for dname in entry.get("dns_names", []):
                        dname = dname.strip().lower().lstrip("*.")
                        if dname and (dname.endswith(f".{domain}") or dname == domain):
                            subdomains.add(dname)
    except Exception as e:
        logger.debug(f"[EASM] Certspotter error for {domain}: {e}")
    return list(subdomains)


async def _alienvault_subdomains(domain: str) -> list[str]:
    """
    Query AlienVault OTX Passive DNS for historical and active subdomains.
    """
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    subdomains: set[str] = set()
    try:
        resp = await _HTTP_CLIENT.get(url, timeout=8.0)
        if resp.status_code == 200:
            data = resp.json()
            records = data.get("passive_dns", [])
            for r in records:
                hn = r.get("hostname", "").strip().lower().lstrip("*.")
                if hn and (hn.endswith(f".{domain}") or hn == domain):
                    subdomains.add(hn)
    except Exception as e:
        logger.debug(f"[EASM] AlienVault OTX error for {domain}: {e}")
    return list(subdomains)


async def _anubis_subdomains(domain: str) -> list[str]:
    """
    Query Anubis database for passive subdomain discovery.
    """
    url = f"https://jldc.me/anubis/subdomains/{domain}"
    subdomains: set[str] = set()
    try:
        resp = await _HTTP_CLIENT.get(url, timeout=8.0)
        if resp.status_code == 200:
            data = resp.json()
            if isinstance(data, list):
                for s in data:
                    s_clean = s.strip().lower().lstrip("*.")
                    if s_clean and (s_clean.endswith(f".{domain}") or s_clean == domain):
                        subdomains.add(s_clean)
    except Exception as e:
        logger.debug(f"[EASM] Anubis error for {domain}: {e}")
    return list(subdomains)


async def _hackertarget_subdomains(domain: str) -> list[str]:
    """
    Query HackerTarget passive DNS for subdomains.
    """
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    subdomains: set[str] = set()
    try:
        resp = await _HTTP_CLIENT.get(url, timeout=8.0)
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

