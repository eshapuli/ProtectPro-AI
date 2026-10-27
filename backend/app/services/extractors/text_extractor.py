import re
import unicodedata
from typing import List, Tuple
from app.schemas.analysis import TextExtractionResult

URL_PATTERN = re.compile(
    r'(?:(?:https?|ftp)://|www\.)[^\s/$.?#].[^\s]*|'
    r'\b(?:[a-zA-Z0-9-]+\.)+(?:com|org|net|edu|gov|xyz|top|ru|cn|io|co|info|biz|me|live|club|online|site|app|cc|link|vip|click)\b[^\s]*',
    re.IGNORECASE
)

EMAIL_PATTERN = re.compile(
    r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
)

# Standard international & local phone formats
PHONE_PATTERN = re.compile(
    r'(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'
)

# Common homoglyph character mappings
HOMOGLYPH_MAP = {
    'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'х': 'x', 'у': 'y',  # Cyrillic
    'А': 'A', 'В': 'B', 'С': 'C', 'Е': 'E', 'Н': 'H', 'М': 'M', 'О': 'O', 'Р': 'P', 'Т': 'T', 'Х': 'X',
    '０': '0', '１': '1', '２': '2', '３': '3', '４': '4', '５': '5', '６': '6', '７': '7', '８': '8', '９': '9', # Fullwidth
    '＠': '@', '．': '.', '／': '/', '：': ':',
}

def normalize_adversarial_text(text: str) -> Tuple[str, bool]:
    """
    Normalizes adversarial text:
    - Removes zero-width characters and unusual control characters
    - Normalizes unicode forms (NFKD/NFKC)
    - Replaces known homoglyphs
    - Returns (normalized_text, was_obfuscated)
    """
    if not text:
        return "", False
    
    original = text
    # Remove zero-width spaces, joiners, soft hyphens
    zero_width_chars = ['\u200B', '\u200C', '\u200D', '\uFEFF', '\u00AD']
    has_zero_width = any(c in text for c in zero_width_chars)
    for c in zero_width_chars:
        text = text.replace(c, '')
        
    # Replace homoglyphs
    has_homoglyphs = False
    cleaned_chars = []
    for ch in text:
        if ch in HOMOGLYPH_MAP:
            cleaned_chars.append(HOMOGLYPH_MAP[ch])
            has_homoglyphs = True
        else:
            cleaned_chars.append(ch)
    text = "".join(cleaned_chars)
    
    # Normalize Unicode NFKC
    nfkc_text = unicodedata.normalize('NFKC', text)
    
    # Compress irregular whitespace
    normalized = re.sub(r'\s+', ' ', nfkc_text).strip()
    
    was_obfuscated = has_zero_width or has_homoglyphs or (normalized != original.strip())
    return normalized, was_obfuscated

def extract_entities_from_text(raw_text: str) -> TextExtractionResult:
    """
    Performs entity extraction on raw text.
    """
    normalized, _ = normalize_adversarial_text(raw_text)
    
    urls = [m.group(0).rstrip('.,;:)') for m in URL_PATTERN.finditer(raw_text)]
    emails = [m.group(0) for m in EMAIL_PATTERN.finditer(raw_text)]
    phones = [m.group(0) for m in PHONE_PATTERN.finditer(raw_text)]
    
    # Also check normalized text for any hidden URLs/emails
    norm_urls = [m.group(0).rstrip('.,;:)') for m in URL_PATTERN.finditer(normalized)]
    for u in norm_urls:
        if u not in urls:
            urls.append(u)
            
    return TextExtractionResult(
        raw_text=raw_text,
        normalized_text=normalized,
        extracted_urls=list(set(urls)),
        extracted_emails=list(set(emails)),
        extracted_phones=list(set(phones))
    )
