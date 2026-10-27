import re
from typing import List
from app.schemas.analysis import IndicatorResult, TextExtractionResult
from app.services.extractors.text_extractor import normalize_adversarial_text

# Deterministic Scam Signal Signatures
URGENCY_PATTERNS = [
    (r'\b(?:urgent|immediately|within 24 hours|within 12 hours|act now|time sensitive|expires today|final notice)\b', 'High Urgency Phrasing', 15),
    (r'\b(?:account suspended|account blocked|access restricted|temporary lock|security alert|unauthorized transaction)\b', 'Account Threat / Suspension Warning', 25),
    (r'\b(?:verify your identity|confirm your identity|update billing|reactivate your account)\b', 'Urgent Identity Verification Demand', 20),
]

CREDENTIAL_HARVESTING_PATTERNS = [
    (r'\b(?:enter your (?:password|pin|passcode|otp|cvv|security code|credentials))\b', 'Explicit Credential Request', 35),
    (r'\b(?:share your (?:otp|code|one-time password|secret key|seed phrase))\b', 'Direct OTP / Secret Solicitation', 40),
    (r'\b(?:login to verify|click here to verify|sign in below)\b', 'Credential Phishing Call to Action', 20),
]

FINANCIAL_SCAM_PATTERNS = [
    (r'\b(?:claim your (?:reward|prize|inheritance|refund|cashback|grant|lottery))\b', 'Unsolicited Financial Windfall / Prize Claim', 25),
    (r'\b(?:guaranteed return|100% profit|crypto investment|bitcoin mining|double your money)\b', 'High-Risk Investment / Crypto Scheme', 30),
    (r'\b(?:wire transfer|gift cards?|apple pay|western union|zelle|cashapp)\b', 'Irreversible Payment Channel Mentioned', 15),
]

DELIVERY_IMPERSONATION_PATTERNS = [
    (r'\b(?:package cannot be delivered|delivery failed|unpaid customs fee|postal tracking|reschedule delivery)\b', 'Package Delivery Impersonation', 20),
]

AUTHORITY_PRESSURE_PATTERNS = [
    (r'\b(?:law enforcement|arrest warrant|fbi|irs|legal action|court summons|tax fraud)\b', 'Legal / Authority Intimidation', 30),
]

def analyze_text_rules(extraction: TextExtractionResult) -> List[IndicatorResult]:
    """
    Applies deterministic security rules to text.
    Extracts measurable, reproducible indicators with evidence snippets.
    """
    indicators: List[IndicatorResult] = []
    text_to_scan = extraction.normalized_text.lower()
    
    # Check for adversarial obfuscation
    _, was_obfuscated = normalize_adversarial_text(extraction.raw_text)
    if was_obfuscated:
        indicators.append(
            IndicatorResult(
                indicator_type="Adversarial Text Obfuscation",
                value="Hidden characters / homoglyphs detected",
                weight=20,
                evidence="Submission contains zero-width unicode, character substitutions, or obfuscated formatting often used to evade spam filters."
            )
        )
    
    # Pattern Categories
    categories = [
        (URGENCY_PATTERNS, "Urgency & Threat Pressure"),
        (CREDENTIAL_HARVESTING_PATTERNS, "Credential Harvesting Attempt"),
        (FINANCIAL_SCAM_PATTERNS, "Financial / Windfall Fraud"),
        (DELIVERY_IMPERSONATION_PATTERNS, "Delivery Scam Pattern"),
        (AUTHORITY_PRESSURE_PATTERNS, "Authority Coercion"),
    ]
    
    for pattern_list, category_name in categories:
        for regex, desc, weight in pattern_list:
            match = re.search(regex, text_to_scan, re.IGNORECASE)
            if match:
                snippet = match.group(0)
                indicators.append(
                    IndicatorResult(
                        indicator_type=category_name,
                        value=snippet,
                        weight=weight,
                        evidence=f"{desc} identified: '{snippet}'."
                    )
                )
                
    # Check for suspicious combinations: Link present + Urgency/Credential/Financial
    if extraction.extracted_urls:
        has_risk_indicators = any(ind.weight >= 20 for ind in indicators)
        if has_risk_indicators:
            indicators.append(
                IndicatorResult(
                    indicator_type="Suspicious Link with Threat/Urgency Context",
                    value=", ".join(extraction.extracted_urls[:3]),
                    weight=15,
                    evidence=f"Text contains actionable URLs alongside coercive or credential-related language ({len(extraction.extracted_urls)} link(s) found)."
                )
            )
            
    return indicators
