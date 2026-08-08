"""
EASM Scanner Probes: HTTP, TLS, Port, Header, Tech Stack, Path Crawling, & DNS Probes
"""
import asyncio
import logging
import re
import socket
import ssl
import uuid
import warnings
from datetime import datetime, timezone
from typing import Optional

from bs4 import BeautifulSoup
from cryptography import x509
import dns.asyncresolver
import httpx

with warnings.catch_warnings():
    warnings.filterwarnings("ignore", category=UserWarning)
    from Wappalyzer import Wappalyzer, WebPage

from app.services.cve_service import CveLookupService
from app.services.easm.config import (
    _HTTP_CLIENT,
    FINGERPRINTS,
    HEADER_WEIGHTS,
    SENSITIVE_PATH_SIGNATURES,
    SUSPICIOUS_PATTERNS,
    logger,
)

_WAPPALYZER = None


def _get_wappalyzer():
    global _WAPPALYZER
    if _WAPPALYZER is None:
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", category=UserWarning)
            _WAPPALYZER = Wappalyzer.latest()
    return _WAPPALYZER


def _grade_security_headers(headers: dict) -> str:
    grade, _, _ = _grade_security_headers_detailed(headers)
    return grade


def _grade_security_headers_detailed(headers: dict) -> tuple[str, int, list[str]]:
    """
    Weighted Security Header Scoring Engine:
      CSP: 30 pts, HSTS: 25 pts, X-Frame-Options: 15 pts,
      X-Content-Type-Options: 15 pts, Referrer-Policy: 10 pts, Permissions-Policy: 5 pts
    Score Mapping:
      90-100 -> Grade A (Excellent)
      75-89  -> Grade B (Good)
      60-74  -> Grade C (Fair)
      40-59  -> Grade D (Poor)
      < 40   -> Grade F (Critical Hardening Needed)
    Returns (grade, score, missing_headers_list)
    """
    h_lower = {k.lower(): v for k, v in headers.items()}
    score = 0
    missing = []
    for h, weight in HEADER_WEIGHTS.items():
        if h in h_lower:
            score += weight
        else:
            missing.append(h)

    if score >= 90:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"

    return grade, score, missing


def _detect_tech_stack(url: str, headers: dict, html: str) -> list[dict]:
    """
    Detect tech stack using Wappalyzer + robust multi-layer manual fallbacks.
    Handles JS-heavy SPAs, PHP frameworks, CDN-served sites, etc.
    Returns: [{"name": "Nginx", "version": "1.18.0"}, ...]
    """
    result = []
    try:
        wapp = _get_wappalyzer()
        page = WebPage(url, html=html, headers=headers)
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", category=UserWarning)
            analysis = wapp.analyze_with_versions_and_categories(page)
        for tech_name, data in analysis.items():
            versions = data.get("versions", [])
            v = versions[0] if versions else ""
            result.append({"name": tech_name, "version": v})
    except Exception as e:
        logger.warning(f"Wappalyzer failed for {url}: {e}")

    existing_names = {t["name"].lower() for t in result}
    h_lower = {k.lower(): v for k, v in headers.items()}
    html_lower = html.lower()

    def _add(name: str, version: str = ""):
        if name.lower() not in existing_names:
            result.append({"name": name, "version": version})
            existing_names.add(name.lower())

    # ── Layer 1: Response Headers ──────────────────────────────────────────────
    server = h_lower.get("server", "")
    x_powered = h_lower.get("x-powered-by", "")
    x_generator = h_lower.get("x-generator", "")
    via = h_lower.get("via", "")
    cf_ray = h_lower.get("cf-ray", "")

    if "nginx" in server:
        v = re.search(r"nginx/([\d.]+)", server)
        _add("Nginx", v.group(1) if v else "")
    if "apache" in server:
        v = re.search(r"apache/([\d.]+)", server, re.IGNORECASE)
        _add("Apache HTTP Server", v.group(1) if v else "")
    if "litespeed" in server.lower():
        _add("LiteSpeed")
    if "openresty" in server.lower():
        _add("OpenResty")
    if "caddy" in server.lower():
        _add("Caddy")
    if "iis" in server.lower():
        v = re.search(r"iis/([\d.]+)", server, re.IGNORECASE)
        _add("IIS", v.group(1) if v else "")

    if "php" in x_powered.lower():
        v = re.search(r"php/([\d.]+)", x_powered, re.IGNORECASE)
        _add("PHP", v.group(1) if v else "")
    if "laravel" in x_powered.lower():
        _add("Laravel")
    if "express" in x_powered.lower():
        _add("Express")
    if "asp.net" in x_powered.lower():
        v = re.search(r"asp\.net mvc ([\d.]+)", x_powered, re.IGNORECASE)
        _add("ASP.NET MVC", v.group(1) if v else "")
        _add("ASP.NET")

    if cf_ray or "cloudflare" in server.lower() or "cloudflare" in via.lower():
        _add("Cloudflare")
    if "varnish" in via.lower() or "varnish" in server.lower():
        _add("Varnish")
    if "fastly" in via.lower() or "fastly" in server.lower():
        _add("Fastly")
    if "akamai" in via.lower():
        _add("Akamai")

    if x_generator:
        if "wordpress" in x_generator.lower():
            _add("WordPress")
        elif "drupal" in x_generator.lower():
            _add("Drupal")

    # ── Layer 2: HTML Meta Tags & Generator Tags ───────────────────────────────
    gen_match = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', html, re.IGNORECASE)
    if gen_match:
        gen = gen_match.group(1).lower()
        if "wordpress" in gen:
            v = re.search(r"wordpress ([\d.]+)", gen_match.group(1), re.IGNORECASE)
            _add("WordPress", v.group(1) if v else "")
        elif "joomla" in gen:
            _add("Joomla")
        elif "drupal" in gen:
            _add("Drupal")
        elif "wix" in gen:
            _add("Wix")
        elif "shopify" in gen:
            _add("Shopify")
        elif "squarespace" in gen:
            _add("Squarespace")
        elif "hugo" in gen:
            _add("Hugo")
        elif "jekyll" in gen:
            _add("Jekyll")
        elif "gatsby" in gen:
            _add("Gatsby")

    # ── Layer 3: HTML Body Patterns ────────────────────────────────────────────
    # Next.js
    if "next.js" not in existing_names:
        if "_next/static" in html or "__NEXT_DATA__" in html or "self.__next_f" in html:
            _add("Next.js")

    # React
    if "react" not in existing_names:
        if "next.js" in existing_names or "data-reactroot" in html or "__REACT_DEVTOOLS_GLOBAL_HOOK__" in html or "react-dom" in html_lower:
            _add("React")

    # Vue.js
    if "vue.js" not in existing_names and "vue" not in existing_names:
        if "data-v-" in html or "__vue_app__" in html or "vue.runtime.esm" in html_lower or "createapp" in html_lower:
            v = re.search(r"vue@([\d.]+)", html)
            _add("Vue.js", v.group(1) if v else "")

    # Alpine.js
    if "alpine.js" not in existing_names:
        if "x-data=" in html or "x-bind:" in html or "@click=" in html or "alpine" in html_lower and "cdn" in html_lower:
            _add("Alpine.js")

    # Laravel (server-side rendered)
    if "laravel" not in existing_names:
        if "laravel_session" in html_lower or "laravel" in html_lower or "_token" in html and "csrf" in html_lower:
            _add("Laravel")

    # Livewire (Laravel component)
    if "livewire" not in existing_names:
        if "wire:id=" in html or "livewire/livewire.js" in html_lower or "livewire" in html_lower:
            _add("Livewire")

    # Inertia.js (InvoiceNinja uses this)
    if "inertia" not in existing_names:
        if 'id="app"' in html and 'data-page=' in html:
            _add("Inertia.js")
        elif "inertia" in html_lower and "component" in html_lower:
            _add("Inertia.js")

    # Tailwind CSS
    if "tailwind css" not in existing_names and "tailwindcss" not in existing_names:
        if "tailwindcss" in html_lower or "tw-" in html or re.search(r'class="[^"]*(?:flex|grid|px-|py-|text-|bg-|font-)[^"]*"', html):
            _add("Tailwind CSS")

    # Bootstrap
    if "bootstrap" not in existing_names:
        if "bootstrap" in html_lower and ("btn-" in html or "col-md-" in html or "navbar" in html_lower):
            v = re.search(r"bootstrap@([\d.]+)", html) or re.search(r"bootstrap/([\d.]+)/", html)
            _add("Bootstrap", v.group(1) if v else "")

    # jQuery
    if "jquery" not in existing_names:
        v = re.search(r"jquery[.-]([\d.]+)", html_lower) or re.search(r"jquery/([\d.]+)/", html_lower)
        if "jquery" in html_lower:
            _add("jQuery", v.group(1) if v else "")

    # Angular
    if "angular" not in existing_names:
        if "ng-version=" in html or "_nghost-" in html or "ng-app=" in html:
            v = re.search(r"ng-version=[\"']([\d.]+)", html)
            _add("Angular", v.group(1) if v else "")

    # Svelte
    if "svelte" not in existing_names:
        if "svelte" in html_lower and ("__svelte" in html or "svelte-" in html):
            _add("Svelte")

    # WordPress specific patterns
    if "wordpress" not in existing_names:
        if "wp-content/" in html or "wp-includes/" in html or "wp-json" in html_lower:
            _add("WordPress")
        if "wordpress" in existing_names and "woocommerce" not in existing_names:
            if "woocommerce" in html_lower:
                _add("WooCommerce")

    # Shopify
    if "shopify" not in existing_names:
        if "cdn.shopify.com" in html_lower or "shopify.com/s/files" in html_lower:
            _add("Shopify")

    # Webflow
    if "webflow" not in existing_names:
        if "webflow.com" in html_lower or 'data-wf-' in html:
            _add("Webflow")

    # Nuxt.js
    if "nuxt.js" not in existing_names and "nuxt" not in existing_names:
        if "__nuxt" in html or "_nuxt/" in html or "nuxt" in html_lower:
            _add("Nuxt.js")

    # Gatsby
    if "gatsby" not in existing_names:
        if "gatsby-" in html_lower or "___gatsby" in html:
            _add("Gatsby")

    # Astro
    if "astro" not in existing_names:
        if "astro-" in html_lower or "<astro-" in html_lower:
            _add("Astro")

    # Ruby on Rails
    if "ruby on rails" not in existing_names:
        if "rails" in html_lower and ("authenticity_token" in html_lower or "data-turbo" in html):
            _add("Ruby on Rails")

    # Django
    if "django" not in existing_names:
        if "csrfmiddlewaretoken" in html_lower or "django" in html_lower:
            _add("Django")

    # ASP.NET
    if "asp.net" not in existing_names:
        if "__viewstate" in html_lower or "asp.net" in html_lower:
            _add("ASP.NET")

    return result


async def _calculate_cve_data(tech_stack: list[dict]) -> list[dict]:
    """Fetch actual CVE data from CveLookupService."""
    cve_service = CveLookupService()
    all_cves = []
    for tech in tech_stack:
        cves = await cve_service.get_cves_for_tech(tech["name"], tech.get("version", ""))
        all_cves.extend(cves)
    await cve_service.close()
    return all_cves


async def _get_catch_all_details(base_url: str) -> Optional[dict]:
    """
    Request multiple random non-existent paths to get catch-all response details if status is 200.
    """
    random_path1 = f"cx-{uuid.uuid4().hex[:8]}-random"
    random_path2 = f"cx-{uuid.uuid4().hex[:8]}-test.php"
    test_url1 = f"{base_url.rstrip('/')}/{random_path1}"
    test_url2 = f"{base_url.rstrip('/')}/{random_path2}"
    try:
        resp1 = await _HTTP_CLIENT.get(test_url1)
        if resp1.status_code == 200:
            try:
                resp2 = await _HTTP_CLIENT.get(test_url2)
            except Exception:
                resp2 = None
            return {
                "random_path": random_path1,
                "random_path2": random_path2,
                "status_code": resp1.status_code,
                "content": resp1.content,
                "content2": resp2.content if (resp2 and resp2.status_code == 200) else resp1.content,
                "body_len": len(resp1.content),
                "headers": dict(resp1.headers),
                "content_type": resp1.headers.get("Content-Type", "").lower()
            }
    except Exception as e:
        logger.debug(f"Catch-all probe details {base_url}: {e}")
    return None


async def _test_catch_all(base_url: str) -> bool:
    """
    Test if the server is a catch-all by requesting a random non-existent path.
    """
    details = await _get_catch_all_details(base_url)
    return details is not None


async def _crawl_links(base_url: str) -> set[str]:
    """Crawl homepage, robots.txt, and sitemap.xml for paths."""
    paths = set()
    try:
        # Crawl root
        resp = await _HTTP_CLIENT.get(base_url)
        if resp.status_code == 200:
            soup = BeautifulSoup(resp.content, "html.parser")
            for a in soup.find_all("a", href=True):
                href = a["href"]
                if href.startswith("/"):
                    paths.add(href)
            # Find fetch calls in inline scripts
            for script in soup.find_all("script"):
                if script.string:
                    for match in re.findall(r'fetch\(([\'"])(.*?)\1\)', script.string):
                        if match[1].startswith("/"):
                            paths.add(match[1])

        # Crawl robots.txt
        robots_url = f"{base_url.rstrip('/')}/robots.txt"
        resp = await _HTTP_CLIENT.get(robots_url)
        if resp.status_code == 200:
            for line in resp.text.splitlines():
                if line.lower().startswith("disallow:") or line.lower().startswith("allow:"):
                    parts = line.split(":", 1)
                    if len(parts) > 1:
                        path = parts[1].strip()
                        if path and path.startswith("/"):
                            paths.add(path)

        # Recursive Directory Listing Check
        # Check if any paths look like directories (e.g. /ftp, /backup) and see if they list files
        dirs_to_check = {p for p in paths if not "." in p.split("/")[-1]}
        for dir_path in list(dirs_to_check)[:10]:  # Limit to avoid excessive requests
            dir_url = f"{base_url.rstrip('/')}{dir_path}"
            if not dir_url.endswith("/"):
                dir_url += "/"
            dir_resp = await _HTTP_CLIENT.get(dir_url)
            if dir_resp.status_code == 200 and ("Index of" in dir_resp.text or "listing directory" in dir_resp.text.lower()):
                paths.add(f"{dir_path.rstrip('/')}/")  # Add the explicit directory path
                soup = BeautifulSoup(dir_resp.content, "html.parser")
                for a in soup.find_all("a", href=True):
                    href = a["href"]
                    if href and not href.startswith("?") and not href.startswith("/"):
                        # Reconstruct full path
                        full_path = f"{dir_path.rstrip('/')}/{href}"
                        paths.add(full_path)

        # Crawl sitemap.xml
        sitemap_url = f"{base_url.rstrip('/')}/sitemap.xml"
        resp = await _HTTP_CLIENT.get(sitemap_url)
        if resp.status_code == 200:
            soup = BeautifulSoup(resp.content, "xml")  # Or html.parser if lxml not present
            for loc in soup.find_all("loc"):
                if loc.string and loc.string.startswith(base_url):
                    path = loc.string[len(base_url.rstrip('/')):]
                    if path.startswith("/"):
                        paths.add(path)
    except Exception as e:
        logger.debug(f"Crawl error {base_url}: {e}")
    return paths


async def _analyze_javascript(base_url: str) -> set[str]:
    """Extract and analyze linked JS bundles."""
    paths = set()
    try:
        resp = await _HTTP_CLIENT.get(base_url)
        if resp.status_code != 200:
            return paths

        soup = BeautifulSoup(resp.content, "html.parser")
        js_links = [script["src"] for script in soup.find_all("script", src=True)]

        # Limit to first 10 JS bundles to save time but still catch main logic
        for js_link in js_links[:10]:
            if js_link.startswith("/"):
                js_url = f"{base_url.rstrip('/')}{js_link}"
            elif js_link.startswith("http"):
                if not js_link.startswith(base_url):
                    continue  # Skip external JS
                js_url = js_link
            else:
                js_url = f"{base_url.rstrip('/')}/{js_link}"

            try:
                js_resp = await _HTTP_CLIENT.get(js_url)
                if js_resp.status_code == 200:
                    content = js_resp.text[:5000000]  # Read up to 5MB
                    # Look for hardcoded API routes, staging URLs, cloud buckets
                    # Capture broad common patterns for SPAs
                    for match in re.findall(r'[\'"](?:/(?:api|rest|b2b|admin|ftp|v[1-9]|staging)[a-zA-Z0-9_\-\/]*)[\'"]', content):
                        paths.add(match.strip("\'\""))

                    # Extract SPA router paths (e.g. path: 'score-board')
                    for match in re.findall(r'path\s*:\s*[\'"]([^\'"]+)[\'"]', content):
                        if match and not match.startswith("*"):
                            paths.add(f"/{match.strip('/')}")
                            paths.add(f"/#/{match.strip('/')}")
                    for match in re.findall(r'https://[a-zA-Z0-9-]+\.s3\.amazonaws\.com', content):
                        paths.add(match)
            except Exception as e:
                logger.debug(f"JS analysis error {js_url}: {e}")

    except Exception as e:
        logger.debug(f"JS extraction error {base_url}: {e}")
    return paths


async def _probe_sensitive_paths(base_url: str, is_catch_all: bool = False) -> list[dict]:
    """
    High-signal path probing for exposed sensitive files, with crawling, JS analysis,
    pattern matching, and response fingerprinting.
    """
    findings = []

    catch_all_details = None
    if is_catch_all:
        catch_all_details = await _get_catch_all_details(base_url)

    crawled_paths = await _crawl_links(base_url)
    js_paths = await _analyze_javascript(base_url)

    all_paths_to_probe = set([p["path"] for p in SENSITIVE_PATH_SIGNATURES])
    all_paths_to_probe.update(crawled_paths)
    all_paths_to_probe.update([p for p in js_paths if p.startswith("/")])

    sem = asyncio.Semaphore(15)  # Concurrency limit for path probing

    async def _probe(path: str):
        async with sem:
            url = f"{base_url.rstrip('/')}{path}"
            try:
                resp = await _HTTP_CLIENT.get(url)

                # 1. Check Response Fingerprints (regardless of path or 200 status)
                for fp in FINGERPRINTS:
                    if fp["regex"].search(resp.text) or (fp["regex"].pattern == 'x-jenkins' and 'x-jenkins' in resp.headers):
                        return {
                            "path": path,
                            "type": fp["type"],
                            "severity": fp["severity"],
                            "url": url,
                            "matched_keyword": f"Fingerprint: {fp['app']}"
                        }

                if resp.status_code == 200:
                    # Guardrail 0: Redirect Guardrail (Reject if redirected to a different path stem, different host, or SSO login page)
                    if resp.history:
                        import urllib.parse
                        parsed_init = urllib.parse.urlparse(str(resp.history[0].url))
                        parsed_final = urllib.parse.urlparse(str(resp.url))

                        # Rejection 1: Redirected to a different host / domain
                        if parsed_init.netloc != parsed_final.netloc:
                            return None

                        # Rejection 2: Redirected to a different path stem
                        init_path = parsed_init.path.rstrip('/')
                        final_path = parsed_final.path.rstrip('/')
                        if init_path and final_path and init_path != final_path:
                            return None

                    # Rejection 3: Redirected to standard SSO / Login / Landing page
                    final_url_lower = str(resp.url).lower()
                    if any(lg in final_url_lower for lg in ["/wp-login", "/login", "/sso/", "/openid-connect", "/oauth/authorize", "page-not-found"]):
                        if not path.startswith("/wp-login") and not path.startswith("/login"):
                            return None

                    content_type = resp.headers.get("Content-Type", "").lower()
                    body_text = resp.text

                    # Guardrail 1: If a captcha/challenge page, drop it
                    if "captcha" in body_text.lower() and "challenge" in body_text.lower():
                        return None

                    # Guardrail 2: Backup manifests (.bak, .zip, .old, .sql) are NEVER text/html files
                    is_backup_ext = any(path.endswith(ext) for ext in [".bak", ".old", ".zip", ".sql"])
                    if is_backup_ext and "text/html" in content_type:
                        return None

                    # Guardrail 3: Tech-stack mismatch for backend script files (e.g. .php, .asp, .jsp) on JS frameworks
                    is_backend_script = any(path.lower().endswith(ext) for ext in [".php", ".asp", ".aspx", ".jsp", ".jspx", ".cgi"])
                    if is_backend_script:
                        headers_lower = {k.lower(): v.lower() for k, v in resp.headers.items()}
                        powered_by = headers_lower.get("x-powered-by", "")
                        server_header_val = headers_lower.get("server", "")

                        is_js_framework = (
                            "next.js" in powered_by or
                            "nextjs" in powered_by or
                            "nuxt" in powered_by or
                            "vercel" in server_header_val or
                            "netlify" in server_header_val or
                            "x-nextjs-cache" in headers_lower or
                            "x-vercel-cache" in headers_lower or
                            "x-nf-request-id" in headers_lower
                        )
                        if is_js_framework:
                            return None

                    # Guardrail 4: Non-HTML files (config, source control, credentials, etc.) are NEVER HTML files
                    NON_HTML_TYPES = {
                        "Configuration Exposure",
                        "Source Control Leak",
                        "Package Manifest",
                        "Docker Configuration",
                        "Backup Exposure",
                        "Database Dump",
                        "File Metadata Leak",
                        "Server Configuration",
                        "Credential Exposure",
                        "IIS Configuration",
                        "Cross-Domain Policy"
                    }
                    is_html = "text/html" in content_type or body_text.strip().lower().startswith(("<!doctype html", "<html"))

                    signature = next((s for s in SENSITIVE_PATH_SIGNATURES if s["path"] == path), None)
                    if is_html and signature and signature["type"] in NON_HTML_TYPES:
                        return None

                    # Guardrail 5: Catch-all / Wildcard response checks
                    if catch_all_details or is_catch_all:
                        if catch_all_details:
                            # Exact content match against baseline 1 or 2
                            if resp.content == catch_all_details["content"] or resp.content == catch_all_details.get("content2"):
                                return None

                            # Replaced path match (in case requested path is reflected in catch-all response)
                            try:
                                random_path_str = catch_all_details["random_path"]
                                r_path = f"/{random_path_str.lstrip('/')}"
                                p_path = f"/{path.lstrip('/')}"

                                catch_all_str = catch_all_details["content"].decode('utf-8', errors='ignore')
                                resp_str = resp.content.decode('utf-8', errors='ignore')

                                replaced_str = catch_all_str.replace(r_path, p_path).replace(random_path_str, path.lstrip('/'))
                                if replaced_str == resp_str:
                                    return None
                            except Exception:
                                pass

                            # Length match threshold for HTML pages
                            if is_html:
                                catch_all_len = catch_all_details.get("body_len", len(catch_all_details["content"]))
                                resp_len = len(resp.content)
                                if abs(catch_all_len - resp_len) < max(100, catch_all_len * 0.05):
                                    return None

                        # If host is catch-all and response is HTML for sensitive path signatures, reject as soft 404
                        if is_catch_all and is_html:
                            if signature and signature["type"] in NON_HTML_TYPES:
                                return None

                    # Strip reflected URL/path tokens from body_text before keyword matching
                    clean_body = body_text
                    path_basename = path.split("/")[-1]
                    path_stem = path_basename.split(".")[0] if "." in path_basename else path_basename

                    tokens_to_strip = [url, path, path.lstrip("/"), path_basename, path_stem]
                    for tok in tokens_to_strip:
                        if tok and len(tok) >= 3:
                            clean_body = clean_body.replace(tok, "").replace(tok.lower(), "")

                    clean_body_bytes = clean_body.encode('utf-8', errors='ignore')

                    # 2. Check predefined signatures if it's from the wordlist
                    if signature:
                        for k in signature["keywords"]:
                            if k.encode('utf-8') in clean_body_bytes:
                                return {
                                    "path": path,
                                    "type": signature["type"],
                                    "severity": signature["severity"],
                                    "url": url,
                                    "matched_keyword": k
                                }

                        # Fallback: for .env files, check generic KEY=VALUE pattern
                        if path.startswith("/.env") and "text/html" not in content_type:
                            import re as _re
                            env_lines = _re.findall(r'^[A-Z][A-Z0-9_]{2,}=.+', body_text, _re.MULTILINE)
                            if len(env_lines) >= 3:
                                return {
                                    "path": path,
                                    "type": signature["type"],
                                    "severity": signature["severity"],
                                    "url": url,
                                    "matched_keyword": f"Generic .env ({len(env_lines)} vars detected)"
                                }

                    # 3. Check pattern matching for dynamically discovered paths
                    for pattern in SUSPICIOUS_PATTERNS:
                        if pattern["regex"].search(path):
                            content_type = resp.headers.get("Content-Type", "")

                            if is_catch_all and "text/html" in content_type:
                                continue

                            if pattern["type"] == "Suspicious Extension":
                                if "text/html" in content_type:
                                    continue

                            if pattern["type"] == "Suspicious Extension" and len(resp.content) == 0:
                                continue

                            return {
                                "path": path,
                                "type": pattern["type"],
                                "severity": pattern["severity"],
                                "url": url,
                                "matched_keyword": f"Pattern: {pattern['regex'].pattern}"
                            }

            except Exception:
                pass
            return None

    tasks = [_probe(p) for p in all_paths_to_probe]
    results = await asyncio.gather(*tasks)

    # Deduplicate by path
    found_paths = set()
    for r in results:
        if r and r["path"] not in found_paths:
            findings.append(r)
            found_paths.add(r["path"])

    # Lightweight Fuzzing for Unhandled Exceptions / Error Disclosure
    try:
        fuzz_targets = set()
        for path in all_paths_to_probe:
            if not any(path.lower().endswith(ext) for ext in [".js", ".css", ".png", ".jpg", ".gif", ".ico", ".svg", ".woff", ".ttf", ".txt", ".bak"]):
                fuzz_targets.add(path.split("?")[0])

        fuzz_payload = "?id=1'\""

        async def _fuzz(path: str):
            async with sem:
                url = f"{base_url.rstrip('/')}{path}{fuzz_payload}"
                try:
                    resp = await _HTTP_CLIENT.get(url)
                    if resp.status_code >= 500:
                        content_lower = resp.text.lower()
                        if "traceback (most recent call last)" in content_lower or \
                           "at /" in content_lower or \
                           "node_modules" in content_lower or \
                           "fatal error" in content_lower or \
                           "java.lang." in content_lower:
                            return {
                                "path": path,
                                "type": "Error Disclosure",
                                "severity": "low",
                                "url": url,
                                "matched_keyword": "Stack Trace Exposure"
                            }
                except Exception:
                    pass
                return None

        sample_targets = list(fuzz_targets)[:20]
        fuzz_tasks = [_fuzz(p) for p in sample_targets]
        fuzz_results = await asyncio.gather(*fuzz_tasks)
        for r in fuzz_results:
            if r and r["path"] not in found_paths:
                findings.append(r)
                found_paths.add(r["path"])
    except Exception as e:
        logger.error(f"Fuzzing failed: {e}")

    for bucket in [p for p in js_paths if p.startswith("http")]:
        findings.append({
            "path": bucket,
            "type": "Cloud Bucket Exposure",
            "severity": "medium",
            "url": bucket,
            "matched_keyword": "S3 Bucket"
        })

    return findings


async def _probe_http(hostname: str) -> dict:
    """
    Probe HTTP/HTTPS on a hostname.
    Returns: {status, tech_stack, sec_headers_grade, sec_headers_score, missing_headers, redirect_url, is_catch_all}
    """
    result = {
        "status": None,
        "tech_stack": [],
        "sec_headers_grade": "unknown",
        "sec_headers_score": 0,
        "missing_headers": [],
        "is_catch_all": False,
        "final_url": None,
    }
    targets = [f"https://{hostname}", f"http://{hostname}"]
    for url in targets:
        try:
            resp = await _HTTP_CLIENT.get(url)
            grade, score, missing = _grade_security_headers_detailed(dict(resp.headers))
            result["status"] = resp.status_code
            result["tech_stack"] = _detect_tech_stack(str(resp.url), dict(resp.headers), resp.text)
            result["sec_headers_grade"] = grade
            result["sec_headers_score"] = score
            result["missing_headers"] = missing
            result["final_url"] = str(resp.url)
            result["is_catch_all"] = await _test_catch_all(url)
            break
        except (httpx.TimeoutException, httpx.ConnectError, ssl.SSLError):
            continue
        except Exception as e:
            logger.debug(f"HTTP probe {url}: {e}")
            continue
    return result


async def _probe_tls(hostname: str) -> Optional[dict]:
    """
    Grab TLS certificate details for a hostname on port 443.
    Returns None if no TLS or connection fails.
    """
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(hostname, 443, ssl=ctx, server_hostname=hostname),
            timeout=8.0,
        )
        cert_bin = writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
        writer.close()
        await writer.wait_closed()

        if not cert_bin:
            return None

        cert = x509.load_der_x509_certificate(cert_bin)

        now = datetime.now(timezone.utc)
        valid_from = cert.not_valid_before_utc
        valid_to = cert.not_valid_after_utc
        days_to_expiry = (valid_to - now).days
        is_expired = days_to_expiry < 0

        # Extract issuer
        issuer_attrs = cert.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        if not issuer_attrs:
            issuer_attrs = cert.issuer.get_attributes_for_oid(x509.NameOID.ORGANIZATION_NAME)
        issuer = issuer_attrs[0].value if issuer_attrs else "Unknown"

        # Subject
        subject_attrs = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
        subject_name = subject_attrs[0].value if subject_attrs else hostname

        # SANs
        try:
            ext = cert.extensions.get_extension_for_oid(x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            sans = ext.value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            sans = []

        is_self_signed = cert.issuer == cert.subject

        # Hostname matching check
        def match_domain(target: str, pattern: str) -> bool:
            if not pattern:
                return False
            if pattern.startswith("*."):
                base = pattern[2:]
                parts = target.split('.')
                return len(parts) > 0 and '.'.join(parts[1:]).lower() == base.lower()
            return target.lower() == pattern.lower()

        is_mismatch = True
        if match_domain(hostname, subject_name):
            is_mismatch = False
        for san in sans:
            if match_domain(hostname, san):
                is_mismatch = False

        return {
            "issuer": issuer,
            "subject": subject_name,
            "valid_from": valid_from,
            "valid_to": valid_to,
            "is_expired": is_expired,
            "is_self_signed": is_self_signed,
            "is_mismatch": is_mismatch,
            "days_to_expiry": days_to_expiry,
            "sans": sans,
        }
    except Exception as e:
        logger.debug(f"TLS probe {hostname}: {e}")
        return None


async def _scan_port(host: str, port: int, timeout: float = 2.5) -> bool:
    """
    Try to open a TCP connection to host:port. Returns True if open.
    """
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        writer.close()
        await writer.wait_closed()
        return True
    except Exception:
        return False


async def _resolve_ip(hostname: str) -> Optional[str]:
    """DNS resolve hostname to IPv4 string."""
    try:
        loop = asyncio.get_event_loop()
        info = await loop.getaddrinfo(hostname, None, family=socket.AF_UNSPEC)
        if info:
            return info[0][4][0]
    except Exception:
        pass
    return None


async def _resolve_geoip(ip: str) -> dict:
    """Fetch Provider (ISP/ASN) and Location (Country) for an IP address."""
    result = {"provider": None, "location": None}
    if not ip:
        return result
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(f"http://ip-api.com/json/{ip}?fields=countryCode,isp")
            if resp.status_code == 200:
                data = resp.json()
                result["provider"] = data.get("isp")
                result["location"] = data.get("countryCode")
    except Exception as e:
        logger.debug(f"GeoIP probe {ip}: {e}")
    return result


async def _check_email_security(domain: str) -> dict:
    """Check SPF and DMARC records via DNS."""
    result = {"spf": None, "dmarc": None, "dmarc_policy": "none", "spf_hardfail": False}
    try:
        resolver = dns.asyncresolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 2

        # Check SPF
        try:
            answers = await resolver.resolve(domain, 'TXT')
            for rdata in answers:
                txt = "".join([s.decode('utf-8') for s in rdata.strings])
                if txt.startswith("v=spf1"):
                    result["spf"] = txt
                    if "-all" in txt:
                        result["spf_hardfail"] = True
                    break
        except Exception:
            pass

        # Check DMARC
        try:
            dmarc_domain = f"_dmarc.{domain}"
            answers = await resolver.resolve(dmarc_domain, 'TXT')
            for rdata in answers:
                txt = "".join([s.decode('utf-8') for s in rdata.strings])
                if txt.startswith("v=DMARC1"):
                    result["dmarc"] = txt
                    match = re.search(r'p=(none|quarantine|reject)', txt, re.IGNORECASE)
                    if match:
                        result["dmarc_policy"] = match.group(1).lower()
                    break
        except Exception:
            pass

    except Exception as e:
        logger.debug(f"Email security check failed for {domain}: {e}")

    return result
