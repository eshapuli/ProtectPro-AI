import hashlib
import json
import re
from typing import List, Dict, Any, Tuple
import numpy as np

# Canonical feature terms capturing recurring scam structural motifs
VOCAB_MOTIFS = [
    "urgent", "immediately", "account", "suspended", "blocked", "verify",
    "password", "pin", "otp", "code", "security", "unauthorized",
    "refund", "prize", "winner", "reward", "bitcoin", "crypto", "investment",
    "customs", "delivery", "package", "tracking", "fee", "wire", "transfer",
    "paypal", "apple", "bank", "chase", "microsoft", "amazon", "dhl", "usps"
]

def generate_canonical_hash(text: str, domains: List[str]) -> str:
    """
    Generates a deterministic structural hash based on normalized tokens and extracted infrastructure.
    Normalizes synonyms and minor lexical variations:
    e.g., 'Your account will be blocked' vs 'Your bank account is about to be suspended'
    """
    clean_text = text.lower()
    # Replace common lexical variations with canonical representations
    clean_text = re.sub(r'\b(suspended|blocked|locked|restricted)\b', 'access_denied', clean_text)
    clean_text = re.sub(r'\b(bank account|checking account|profile|account)\b', 'user_account', clean_text)
    clean_text = re.sub(r'\b(immediately|urgent|within \d+ hours|act now)\b', 'time_pressure', clean_text)
    clean_text = re.sub(r'\b(password|pin|otp|passcode|credentials)\b', 'auth_secret', clean_text)
    clean_text = re.sub(r'\b(refund|prize|winner|cashback|inheritance)\b', 'financial_windfall', clean_text)
    
    # Extract canonical tokens
    tokens = sorted(list(set(re.findall(r'\b[a-z_]{4,}\b', clean_text))))
    dom_str = ",".join(sorted(domains))
    canonical_repr = f"TOKENS:{' '.join(tokens)}|DOMAINS:{dom_str}"
    
    return hashlib.sha256(canonical_repr.encode('utf-8')).hexdigest()

def compute_feature_vector(text: str, indicators: List[str], domains: List[str]) -> List[float]:
    """
    Calculates a dense numerical feature vector representation:
    - Motif frequency counts
    - Infrastructure signal presence
    - Structural properties (length, exclamation marks, URL count)
    """
    text_lower = text.lower()
    vector = []
    
    # 1. Term Motif Presence (normalized binary/frequency)
    for motif in VOCAB_MOTIFS:
        count = text_lower.count(motif)
        vector.append(min(float(count), 5.0) / 5.0)
        
    # 2. Structural metrics
    word_count = len(text_lower.split())
    vector.append(min(float(word_count) / 100.0, 1.0))
    vector.append(min(float(text.count('!')) / 5.0, 1.0))
    vector.append(min(float(len(domains)) / 3.0, 1.0))
    vector.append(min(float(len(indicators)) / 5.0, 1.0))
    
    # L2 normalize the vector
    vec_np = np.array(vector, dtype=np.float32)
    norm = np.linalg.norm(vec_np)
    if norm > 0:
        vec_np = vec_np / norm
        
    return [round(float(x), 5) for x in vec_np.tolist()]

def categorize_scam_pattern(text: str, indicators: List[str]) -> str:
    """Classifies scam category deterministically based on extracted evidence."""
    t = text.lower()
    if any(k in t for k in ["bitcoin", "crypto", "investment", "double your", "profit"]):
        return "cryptocurrency_investment"
    elif any(k in t for k in ["package", "delivery", "customs", "usps", "dhl", "postal"]):
        return "delivery_impersonation"
    elif any(k in t for k in ["suspended", "blocked", "password", "otp", "verify your account"]):
        return "credential_phishing"
    elif any(k in t for k in ["prize", "winner", "lottery", "inheritance", "cashback"]):
        return "advance_fee_lottery"
    else:
        return "general_suspicious"

def calculate_cosine_similarity(vec_a: List[float], vec_b: List[float]) -> float:
    """Computes standard cosine similarity between two normalized feature vectors."""
    a = np.array(vec_a, dtype=np.float32)
    b = np.array(vec_b, dtype=np.float32)
    dot = np.dot(a, b)
    norm_a = np.linalg.norm(a)
    norm_b = np.linalg.norm(b)
    if norm_a == 0 or norm_b == 0:
        return 0.0
    sim = dot / (norm_a * norm_b)
    return round(float(np.clip(sim, 0.0, 1.0)), 4)
