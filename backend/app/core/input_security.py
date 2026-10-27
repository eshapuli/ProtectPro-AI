import re
from typing import Tuple

# Common prompt injection triggers
INJECTION_TRIGGERS = [
    r'ignore (?:all )?(?:previous|prior) instructions',
    r'disregard (?:all )?(?:previous|system) (?:prompts|rules)',
    r'you are now in developer mode',
    r'output your system prompt',
    r'reveal your (?:instructions|hidden prompt)',
    r'override safety (?:protocols|filters)',
    r'jailbreak',
    r'act as an unfiltered (?:assistant|model)',
]

def sanitize_untrusted_input(text: str) -> Tuple[str, bool]:
    """
    Sanitizes untrusted submission text:
    - Strips dangerous control sequences
    - Escapes XML/HTML tags to prevent format breakout
    - Detects explicit prompt injection attempts and neutralizes them
    - Returns (sanitized_text, injection_attempt_detected)
    """
    if not text:
        return "", False

    injection_detected = False
    for trigger in INJECTION_TRIGGERS:
        if re.search(trigger, text, re.IGNORECASE):
            injection_detected = True
            break

    # HTML / XML sanitization to prevent tag injection in downstream processors
    clean = text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
    
    # Neutralize null bytes and unprintable terminal escape codes
    clean = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', clean)
    
    return clean, injection_detected
