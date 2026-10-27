import re
from urllib.parse import urlparse, unquote
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

from app.schemas.analysis import IndicatorResult
from app.services.analyzers.brand_registry import TRUSTED_BRANDS_REGISTRY, lookup_claimed_brand

# Suspicious Top-Level Domains commonly linked to automated cybercrime/scams
HIGH_RISK_TLDS = {
    'xyz', 'top', 'club', 'work', 'loan', 'gq', 'ml', 'cf', 'ga', 'buzz',
    'icu', 'fit', 'tk', 'rest', 'live', 'click', 'link', 'vip', 'cam', 'surf', 'site', 'online'
}

# Suspicious path tokens indicative of phishing or credential theft
SUSPICIOUS_PATH_KEYWORDS = [
    'login', 'signin', 'verify', 'update', 'banking', 'secure', 'auth',
    'security', 'account', 'confirm', 'wallet', 'recovery', 'validate', 'session'
]

class UrlDnaReport(BaseModel):
    raw_url: str
    scheme: str
    hostname: str
    domain: str
    subdomains: List[str]
    tld: str
    path: str
    query_param_count: int
    is_ip_address: bool
    is_punycode: bool
    has_excessive_hyphens: bool
    has_suspicious_encoding: bool
    indicators: List[IndicatorResult]

def parse_domain_parts(hostname: str) -> Dict[str, Any]:
    """
    Parses hostname safely without external network calls.
    Returns domain, subdomains, tld, and punycode/ip flags.
    """
    hostname = hostname.lower().strip()
    is_ip = bool(re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$', hostname))
    is_punycode = 'xn--' in hostname
    
    parts = hostname.split('.')
    if len(parts) >= 2:
        tld = parts[-1]
        domain = ".".join(parts[-2:])
        subdomains = parts[:-2]
    else:
        tld = ""
        domain = hostname
        subdomains = []
        
    return {
        "hostname": hostname,
        "domain": domain,
        "subdomains": subdomains,
        "tld": tld,
        "is_ip_address": is_ip,
        "is_punycode": is_punycode
    }

def analyze_url_dna(raw_url: str, context_text: Optional[str] = None) -> UrlDnaReport:
    """
    Deep passive URL DNA inspection:
    - Hostname / IP address detection
    - Suspicious TLD detection
    - Homoglyph / Punycode obfuscation
    - Excessive hyphens and typosquatting tokens
    - Suspicious subdomains and misleading brand embedding
    - Brand impersonation against trusted registry
    """
    indicators: List[IndicatorResult] = []
    
    # Ensure scheme for correct urllib parsing
    url_to_parse = raw_url.strip()
    if not url_to_parse.startswith(('http://', 'https://')):
        url_to_parse = 'http://' + url_to_parse
        
    try:
        parsed = urlparse(url_to_parse)
    except Exception:
        indicators.append(
            IndicatorResult(
                indicator_type="Malformed URL",
                value=raw_url,
                weight=25,
                evidence="The URL string cannot be parsed correctly, indicating possible obfuscation."
            )
        )
        return UrlDnaReport(
            raw_url=raw_url,
            scheme="",
            hostname="",
            domain="",
            subdomains=[],
            tld="",
            path="",
            query_param_count=0,
            is_ip_address=False,
            is_punycode=False,
            has_excessive_hyphens=False,
            has_suspicious_encoding=False,
            indicators=indicators
        )

    scheme = parsed.scheme.lower()
    hostname = parsed.hostname or ""
    path = parsed.path
    query = parsed.query
    query_count = len(query.split('&')) if query else 0
    
    domain_info = parse_domain_parts(hostname)
    domain = domain_info["domain"]
    subdomains = domain_info["subdomains"]
    tld = domain_info["tld"]
    is_ip = domain_info["is_ip_address"]
    is_punycode = domain_info["is_punycode"]
    
    # 1. Scheme Check
    if scheme == "http":
        indicators.append(
            IndicatorResult(
                indicator_type="Insecure Protocol (HTTP)",
                value="http://",
                weight=10,
                evidence="URL uses unencrypted HTTP instead of HTTPS for sensitive communications."
            )
        )
        
    # 2. IP-based URL
    if is_ip:
        indicators.append(
            IndicatorResult(
                indicator_type="Direct IP Address Hostname",
                value=hostname,
                weight=30,
                evidence=f"URL uses a direct raw IP address ({hostname}) rather than a registered domain name."
            )
        )

    # 3. Punycode / Internationalized Domain Name (IDN) Homoglyph
    if is_punycode:
        indicators.append(
            IndicatorResult(
                indicator_type="Punycode / IDN Homoglyph Domain",
                value=hostname,
                weight=35,
                evidence=f"Domain contains punycode ('{hostname}'), often used to visually mimic trusted brand spellings."
            )
        )

    # 4. Suspicious TLD
    if tld in HIGH_RISK_TLDS:
        indicators.append(
            IndicatorResult(
                indicator_type="High-Risk Top-Level Domain (TLD)",
                value=f".{tld}",
                weight=20,
                evidence=f"The domain uses the '.{tld}' TLD, which is statistically overrepresented in disposable phishing campaigns."
            )
        )

    # 5. Excessive Hyphens in Hostname
    has_hyphens = hostname.count('-') >= 2
    if has_hyphens:
        indicators.append(
            IndicatorResult(
                indicator_type="Excessive Hyphenation in Hostname",
                value=hostname,
                weight=15,
                evidence=f"Hostname contains {hostname.count('-')} hyphens, a common pattern in deceptive lookalike domains."
            )
        )

    # 6. Deep Subdomain Nesting
    if len(subdomains) >= 3:
        indicators.append(
            IndicatorResult(
                indicator_type="Excessive Subdomain Stacking",
                value=".".join(subdomains),
                weight=15,
                evidence=f"Hostname has {len(subdomains)} subdomain levels, frequently used to disguise the true registered root domain."
            )
        )

    # 7. Suspicious Path & Query Keywords
    lower_path = path.lower()
    matched_path_tokens = [kw for kw in SUSPICIOUS_PATH_KEYWORDS if kw in lower_path]
    if matched_path_tokens:
        indicators.append(
            IndicatorResult(
                indicator_type="Phishing Path Keywords Detected",
                value=", ".join(matched_path_tokens),
                weight=15,
                evidence=f"URL path targets authentication or account recovery: '{', '.join(matched_path_tokens)}'."
            )
        )

    # 8. Encoded Characters / Obfuscation
    has_suspicious_encoding = ('%20' in raw_url or '%2f' in raw_url.lower() or '@' in raw_url)
    if has_suspicious_encoding:
        indicators.append(
            IndicatorResult(
                indicator_type="Deceptive URL Encoding / Userinfo '@' Trick",
                value=raw_url,
                weight=25,
                evidence="URL contains suspicious character hex-encoding or an '@' symbol used to confuse URL parsers."
            )
        )

    # 9. Brand Impersonation & Registry Matching
    # A) Check if context claims a brand (e.g., text said 'PayPal' but URL is xyz)
    claimed_brand = lookup_claimed_brand(context_text) if context_text else None
    
    # B) Also check if the URL itself includes known brand keywords in hostname/subdomains
    for brand_key, brand_prof in TRUSTED_BRANDS_REGISTRY.items():
        # Check if brand keyword is embedded in a hostname that does NOT belong to the brand
        embedded_in_host = any(kw in hostname for kw in brand_prof.keywords)
        is_legit = any(hostname == leg or hostname.endswith('.' + leg) for leg in brand_prof.legitimate_domains)
        
        if embedded_in_host and not is_legit:
            indicators.append(
                IndicatorResult(
                    indicator_type="Brand Domain Impersonation (Spoofing)",
                    value=f"{brand_prof.brand_name} -> {hostname}",
                    weight=40,
                    evidence=f"Hostname embeds brand keyword '{brand_prof.brand_name}' but does not resolve to an official domain ({', '.join(brand_prof.legitimate_domains)})."
                )
            )
        elif claimed_brand and claimed_brand.brand_name == brand_prof.brand_name and not is_legit:
            # Context claims the brand, but destination URL is completely different
            indicators.append(
                IndicatorResult(
                    indicator_type="Brand / Destination Domain Mismatch",
                    value=f"Claims {claimed_brand.brand_name}, points to {domain}",
                    weight=35,
                    evidence=f"The communication claims to represent {claimed_brand.brand_name}, but provides a link pointing to an unrelated domain '{domain}'."
                )
            )

    return UrlDnaReport(
        raw_url=raw_url,
        scheme=scheme,
        hostname=hostname,
        domain=domain,
        subdomains=subdomains,
        tld=tld,
        path=path,
        query_param_count=query_count,
        is_ip_address=is_ip,
        is_punycode=is_punycode,
        has_excessive_hyphens=has_hyphens,
        has_suspicious_encoding=has_suspicious_encoding,
        indicators=indicators
    )
