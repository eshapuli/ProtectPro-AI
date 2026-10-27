from typing import List
from app.schemas.analysis import IndicatorResult, RiskScoreResult

def calculate_risk_score(indicators: List[IndicatorResult]) -> RiskScoreResult:
    """
    Deterministic Evidence-Based Risk Engine.
    
    Principles:
    - Never uses an LLM to guess a score.
    - Calculated entirely from measurable signals with verifiable weights.
    - Caps at 100.
    - Computes confidence based on indicator density and signal consensus.
    """
    if not indicators:
        return RiskScoreResult(
            score=0,
            risk_level="Safe",
            confidence=0.85,
            contributing_signals=[]
        )
    
    # Cumulative weight calculation
    raw_score = sum(ind.weight for ind in indicators)
    final_score = min(max(raw_score, 0), 100)
    
    # Categorization based on transparent cybersecurity thresholds
    if final_score >= 80:
        level = "Critical"
    elif final_score >= 55:
        level = "High"
    elif final_score >= 30:
        level = "Medium"
    elif final_score > 0:
        level = "Low"
    else:
        level = "Safe"
        
    # Confidence formula: scales with number of corroborating distinct signals
    distinct_types = len(set(ind.indicator_type for ind in indicators))
    confidence = min(0.60 + (distinct_types * 0.10), 0.98)
    
    return RiskScoreResult(
        score=final_score,
        risk_level=level,
        confidence=round(confidence, 2),
        contributing_signals=indicators
    )
