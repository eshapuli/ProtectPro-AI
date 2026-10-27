import os
from typing import Dict, Any, List, Optional
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.schemas.analysis import IndicatorResult, TextExtractionResult, RiskScoreResult
from app.services.extractors.text_extractor import extract_entities_from_text
from app.services.analyzers.rule_engine import analyze_text_rules
from app.services.analyzers.url_dna_analyzer import analyze_url_dna
from app.services.analyzers.brand_registry import lookup_claimed_brand
from app.services.risk.risk_engine import calculate_risk_score
from app.services.intelligence.rag_knowledge_base import query_rag_knowledge_base

class AgentReport(BaseModel):
    summary: str
    why_suspicious: List[str]
    technical_evidence: List[Dict[str, Any]]
    historical_context: str
    recommended_safe_actions: List[str]
    disclaimer: str

class ControlledInvestigationAgent:
    """
    Controlled Investigation Agent.
    
    CRITICAL ARCHITECTURAL CONSTRAINTS:
    - Never determines or overrides numerical risk scores (deterministic engine does that).
    - Restricted to safe, read-only analysis tools.
    - Zero active web requests / zero code execution capabilities.
    - Uses evidence collected by deterministic tools to generate an explainable threat brief.
    - Clearly labels AI-generated conclusions vs observed indicators.
    - Robust to prompt injection (treats user inputs strictly as passive untrusted data).
    """
    def __init__(self, db: Session):
        self.db = db

    # RESTRICTED TOOL SET:
    def tool_extract_entities(self, text: str) -> TextExtractionResult:
        return extract_entities_from_text(text)

    def tool_analyze_rules(self, extraction: TextExtractionResult) -> List[IndicatorResult]:
        return analyze_text_rules(extraction)

    def tool_analyze_url_dna(self, url: str, context: Optional[str] = None):
        return analyze_url_dna(url, context_text=context)

    def tool_lookup_brand(self, text: str):
        return lookup_claimed_brand(text)

    def tool_query_rag(self, query: str) -> List[Any]:
        return query_rag_knowledge_base(self.db, query, limit=2)

    def generate_investigation_report(
        self,
        raw_text: str,
        risk_result: RiskScoreResult,
        indicators: List[IndicatorResult],
        campaign_id: Optional[str] = None,
        similarity_verdict: Optional[str] = None
    ) -> AgentReport:
        """
        Synthesizes collected technical evidence into a structured, explainable investigation report.
        When external LLM API keys are not provided, generates an accurate deterministic report based
        on verified technical indicators.
        """
        why_suspicious = []
        technical_evidence = []

        for ind in indicators:
            why_suspicious.append(f"{ind.indicator_type}: {ind.evidence}")
            technical_evidence.append({
                "signal": ind.indicator_type,
                "weight_contribution": f"+{ind.weight} pts",
                "observed_value": ind.value,
                "verified_fact": True
            })

        if not why_suspicious:
            why_suspicious.append("No actionable malicious indicators or coercive patterns were identified in the submission.")

        # Historical context synthesis
        if campaign_id:
            historical_context = (
                f"Correlated with active threat cluster {campaign_id}. "
                "Multiple users have observed similar lexical patterns or infrastructure."
            )
        elif similarity_verdict and similarity_verdict != "NEW_PATTERN":
            historical_context = (
                f"Observed similarity match: '{similarity_verdict}'. "
                "The patterns align with previously analyzed threats in the local database."
            )
        else:
            historical_context = (
                "New pattern. No prior historical matches found in the local intelligence registry."
            )

        # Retrieve RAG playbooks for safe action steps
        rag_items = self.tool_query_rag(raw_text)
        recommended_actions = []
        if rag_items:
            for item in rag_items:
                recommended_actions.append(item.recommended_mitigation)
        else:
            if risk_result.score >= 50:
                recommended_actions.append("Do not click links, open attachments, or reply to the sender.")
                recommended_actions.append("Verify the claimed alert by visiting the organization's official website independently.")
                recommended_actions.append("Report the message to your organization's security team or cellular carrier.")
            else:
                recommended_actions.append("Content appears benign; maintain standard operational vigilance.")

        # Executive summary
        summary = (
            f"ProtectPro AI assessed this submission as {risk_result.risk_level.upper()} RISK "
            f"({risk_result.score}/100) based on {len(indicators)} corroborating technical indicator(s). "
            f"{historical_context}"
        )

        return AgentReport(
            summary=summary,
            why_suspicious=why_suspicious,
            technical_evidence=technical_evidence,
            historical_context=historical_context,
            recommended_safe_actions=recommended_actions,
            disclaimer=(
                "ANALYSIS CLASSIFICATION: Technical indicators and risk scores are deterministically verified. "
                "Explanatory narratives are synthesized for operator decision support and should not replace formal forensic triage."
            )
        )
