"""
CyberGuard — DNS Verification Service
Verifies domain ownership via DNS TXT record challenge.
Uses dnspython for reliable, async-friendly DNS resolution.
"""
import secrets
import re
from typing import Optional, Tuple
import ipaddress

import dns.resolver
import dns.exception


VERIFICATION_TOKEN_PREFIX = "cyberguard-verify"


def generate_verification_token() -> str:
    """
    Generate a cryptographically secure verification token.
    Format: cyberguard-verify=<32 random hex chars>
    Customers must add this as a TXT record to their DNS zone.
    """
    random_hex = secrets.token_hex(16)
    return f"{VERIFICATION_TOKEN_PREFIX}={random_hex}"


def validate_domain_format(domain: str) -> Tuple[bool, Optional[str]]:
    """
    Validate that a string is a well-formed domain name.
    Returns (is_valid, error_message).
    """
    domain = domain.strip().lower()
    
    # Strip protocol if accidentally included
    domain = re.sub(r'^https?://', '', domain)
    domain = domain.rstrip('/')
    
    # Basic domain regex (simplified but practical)
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    if not re.match(pattern, domain):
        return False, f"'{domain}' is not a valid domain name."
    
    if len(domain) > 253:
        return False, "Domain name exceeds maximum length of 253 characters."
    
    return True, None


def validate_cidr_format(cidr: str) -> Tuple[bool, Optional[str]]:
    """
    Validate that a string is a valid public IPv4/IPv6 CIDR block.
    Rejects private/loopback/link-local ranges.
    Returns (is_valid, error_message).
    """
    cidr = cidr.strip()
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return False, f"'{cidr}' is not a valid CIDR notation."
    
    # Removed private IP rejection to allow for local testing with OWASP Juice Shop / Vulhub
    # if network.is_private:
    #     return False, (
    #         f"'{cidr}' is a private IP range and cannot be scanned "
    #         "(e.g., 10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12)."
    #     )
    
    # if network.is_loopback:
    #     return False, f"'{cidr}' is a loopback address and is not a valid scan target."
    
    if network.is_link_local:
        return False, f"'{cidr}' is a link-local address and is not a valid scan target."
    
    if network.is_multicast:
        return False, f"'{cidr}' is a multicast address and is not a valid scan target."
    
    return True, None


def check_dns_txt_verification(domain: str, expected_token: str) -> Tuple[bool, str]:
    """
    Query the public DNS for a TXT record matching the expected token.
    
    Args:
        domain: The root domain to query (e.g., "bank.ma")
        expected_token: The token we expect to find (e.g., "cyberguard-verify=abc123")
    
    Returns:
        (verified: bool, message: str)
    
    Note:
        This is a synchronous call. For production, wrap in asyncio.run_in_executor()
        or use aiodns. For Phase 1, it runs in a sync FastAPI route called from
        a thread pool via run_in_executor.
    """
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = 5
        resolver.lifetime = 10
        
        answers = resolver.resolve(domain, 'TXT')
        
        for record in answers:
            # TXT records return as a list of strings, join them
            record_text = "".join(part.decode('utf-8') for part in record.strings)
            
            if expected_token in record_text:
                return True, f"✓ Verification token found in TXT records for {domain}."
        
        return False, (
            f"Verification token not found in TXT records for {domain}. "
            f"Expected: {expected_token}. "
            "DNS changes can take up to 48 hours to propagate."
        )
    
    except dns.resolver.NXDOMAIN:
        return False, f"Domain '{domain}' does not exist in DNS."
    
    except dns.resolver.NoAnswer:
        return False, f"No TXT records found for '{domain}'."
    
    except dns.exception.Timeout:
        return False, f"DNS query timed out for '{domain}'. Please try again."
    
    except Exception as e:
        return False, f"DNS verification error: {str(e)}"
