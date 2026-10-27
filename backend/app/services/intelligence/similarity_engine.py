import json
from typing import List, Optional
from pydantic import BaseModel
from sqlalchemy.orm import Session
from datetime import datetime

from app.models.user import Fingerprint, Analysis
from app.services.intelligence.fingerprint_engine import (
    generate_canonical_hash, compute_feature_vector,
    categorize_scam_pattern, calculate_cosine_similarity
)

class SimilarMatchResult(BaseModel):
    analysis_id: int
    similarity_score: float # 0.0 to 1.0
    match_level: str # "EXACT_FINGERPRINT", "STRONG_MATCH", "SIMILAR_PATTERN", "NEW_PATTERN"
    scam_category: str
    shared_domains: List[str]
    matching_signals: List[str] = []
    created_at: datetime

class SimilaritySearchReport(BaseModel):
    verdict: str # "KNOWN_CAMPAIGN", "STRONG_MATCH", "SIMILAR_PATTERN", "NEW_PATTERN"
    highest_similarity: float
    total_historical_matches: int
    matches: List[SimilarMatchResult]

def create_and_store_fingerprint(
    db: Session,
    analysis_id: int,
    text: str,
    indicator_types: List[str],
    domains: List[str]
) -> Fingerprint:
    """Creates and persists a cryptographic & vector fingerprint for an analysis."""
    structural_hash = generate_canonical_hash(text, domains)
    category = categorize_scam_pattern(text, indicator_types)
    feature_vec = compute_feature_vector(text, indicator_types, domains)
    
    fp = Fingerprint(
        analysis_id=analysis_id,
        structural_hash=structural_hash,
        extracted_domains=",".join(domains) if domains else "",
        scam_category=category,
        feature_vector=json.dumps(feature_vec)
    )
    db.add(fp)
    db.commit()
    db.refresh(fp)
    return fp

def search_similar_fingerprints(
    db: Session,
    current_analysis_id: int,
    text: str,
    indicator_types: List[str],
    domains: List[str],
    min_similarity_threshold: float = 0.70,
    user_id: Optional[int] = None
) -> SimilaritySearchReport:
    """
    'Have I Seen This Before?' Engine:
    Compares the incoming submission against all permitted historical fingerprints.
    Enforces user-level tenant isolation when user_id is provided.
    Finds structural hash collisions and cosine distance matches.
    """
    current_hash = generate_canonical_hash(text, domains)
    current_vec = compute_feature_vector(text, indicator_types, domains)
    current_domains_set = set(domains)
    
    # Query permitted fingerprints with user isolation
    query = db.query(Fingerprint).join(Analysis, Fingerprint.analysis_id == Analysis.id).filter(Fingerprint.analysis_id != current_analysis_id)
    if user_id is not None:
        query = query.filter(Analysis.user_id == user_id)
    historical_fps = query.all()
    
    matches: List[SimilarMatchResult] = []
    
    for prev_fp in historical_fps:
        prev_vec = json.loads(prev_fp.feature_vector)
        sim = calculate_cosine_similarity(current_vec, prev_vec)
        
        # Check if structural hashes match exactly
        is_exact = (current_hash == prev_fp.structural_hash)
        if is_exact:
            sim = max(sim, 0.98)
            
        if sim >= min_similarity_threshold or is_exact:
            prev_domains = set(prev_fp.extracted_domains.split(',')) if prev_fp.extracted_domains else set()
            shared = list(current_domains_set.intersection(prev_domains))
            
            matching_signals: List[str] = []
            if is_exact:
                level = "EXACT_FINGERPRINT"
                matching_signals.append("Exact structural fingerprint match (identical template)")
            elif sim >= 0.85:
                level = "STRONG_MATCH"
                matching_signals.append("Correlated risk indicator feature vector")
            else:
                level = "SIMILAR_PATTERN"
                matching_signals.append("Shared scam behavioral pattern")

            if shared:
                for d in shared:
                    matching_signals.append(f"Shared infrastructure domain: {d}")
            if prev_fp.scam_category:
                matching_signals.append(f"Matching category: {prev_fp.scam_category}")
                
            matches.append(
                SimilarMatchResult(
                    analysis_id=prev_fp.analysis_id,
                    similarity_score=sim,
                    match_level=level,
                    scam_category=prev_fp.scam_category,
                    shared_domains=shared,
                    matching_signals=matching_signals,
                    created_at=prev_fp.created_at or datetime.utcnow()
                )
            )
            
    # Sort matches by highest similarity first
    matches.sort(key=lambda m: m.similarity_score, reverse=True)
    
    if not matches:
        return SimilaritySearchReport(
            verdict="NEW_PATTERN",
            highest_similarity=0.0,
            total_historical_matches=0,
            matches=[]
        )
        
    top_score = matches[0].similarity_score
    if top_score >= 0.92 and len(matches) >= 3:
        overall_verdict = "KNOWN_CAMPAIGN"
    elif top_score >= 0.85:
        overall_verdict = "STRONG_MATCH"
    else:
        overall_verdict = "SIMILAR_PATTERN"
        
    return SimilaritySearchReport(
        verdict=overall_verdict,
        highest_similarity=top_score,
        total_historical_matches=len(matches),
        matches=matches[:10] # Return top 10 matches
    )
