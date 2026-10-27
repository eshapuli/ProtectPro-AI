from typing import Dict, List, Optional
from pydantic import BaseModel

class BrandProfile(BaseModel):
    brand_name: str
    primary_domain: str
    legitimate_domains: List[str]
    keywords: List[str]

# Trusted Registry of commonly impersonated institutions & brands
TRUSTED_BRANDS_REGISTRY: Dict[str, BrandProfile] = {
    "paypal": BrandProfile(
        brand_name="PayPal",
        primary_domain="paypal.com",
        legitimate_domains=["paypal.com", "paypal-communication.com", "paypal-community.com"],
        keywords=["paypal", "pay-pal", "paypal-service"]
    ),
    "apple": BrandProfile(
        brand_name="Apple",
        primary_domain="apple.com",
        legitimate_domains=["apple.com", "icloud.com", "itunes.com"],
        keywords=["apple", "icloud", "appleid", "apple-id"]
    ),
    "microsoft": BrandProfile(
        brand_name="Microsoft",
        primary_domain="microsoft.com",
        legitimate_domains=["microsoft.com", "live.com", "office.com", "outlook.com"],
        keywords=["microsoft", "office365", "onedrive", "azure", "windows"]
    ),
    "amazon": BrandProfile(
        brand_name="Amazon",
        primary_domain="amazon.com",
        legitimate_domains=["amazon.com", "amazon.co.uk", "amazon.de", "aws.amazon.com"],
        keywords=["amazon", "prime", "amazon-pay", "aws"]
    ),
    "google": BrandProfile(
        brand_name="Google",
        primary_domain="google.com",
        legitimate_domains=["google.com", "gmail.com", "accounts.google.com"],
        keywords=["google", "gmail", "google-drive"]
    ),
    "chase": BrandProfile(
        brand_name="Chase Bank",
        primary_domain="chase.com",
        legitimate_domains=["chase.com", "jpmorganchase.com"],
        keywords=["chase", "chasebank", "chase-online"]
    ),
    "bankofamerica": BrandProfile(
        brand_name="Bank of America",
        primary_domain="bankofamerica.com",
        legitimate_domains=["bankofamerica.com", "bofa.com"],
        keywords=["bankofamerica", "bofa", "bank-of-america"]
    ),
    "wells_fargo": BrandProfile(
        brand_name="Wells Fargo",
        primary_domain="wellsfargo.com",
        legitimate_domains=["wellsfargo.com"],
        keywords=["wellsfargo", "wells-fargo"]
    ),
    "netflix": BrandProfile(
        brand_name="Netflix",
        primary_domain="netflix.com",
        legitimate_domains=["netflix.com"],
        keywords=["netflix"]
    ),
    "usps": BrandProfile(
        brand_name="USPS",
        primary_domain="usps.com",
        legitimate_domains=["usps.com", "postal-service.usps.com"],
        keywords=["usps", "postalservice", "us-postal"]
    ),
    "dhl": BrandProfile(
        brand_name="DHL",
        primary_domain="dhl.com",
        legitimate_domains=["dhl.com", "dhl-express.com"],
        keywords=["dhl", "dhl-tracking", "dhlexpress"]
    ),
    "ups": BrandProfile(
        brand_name="UPS",
        primary_domain="ups.com",
        legitimate_domains=["ups.com"],
        keywords=["ups", "ups-tracking"]
    ),
}

def lookup_claimed_brand(text: str) -> Optional[BrandProfile]:
    """
    Checks if message text or content claims or strongly references any registered brand.
    """
    text_lower = text.lower()
    for brand_key, profile in TRUSTED_BRANDS_REGISTRY.items():
        for kw in profile.keywords:
            if kw in text_lower:
                return profile
    return None
