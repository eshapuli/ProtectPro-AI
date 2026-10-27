from pydantic import BaseModel, Field
from typing import List, Optional
from datetime import datetime

class IndicatorResult(BaseModel):
    indicator_type: str
    value: Optional[str] = None
    weight: int = 0
    evidence: str

class TextExtractionResult(BaseModel):
    raw_text: str
    normalized_text: str
    extracted_urls: List[str] = Field(default_factory=list)
    extracted_emails: List[str] = Field(default_factory=list)
    extracted_phones: List[str] = Field(default_factory=list)

class RiskScoreResult(BaseModel):
    score: int = Field(ge=0, le=100)
    risk_level: str  # Safe, Low, Medium, High, Critical
    confidence: float
    contributing_signals: List[IndicatorResult]

class TextAnalysisRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=10000)

class TextAnalysisResponse(BaseModel):
    analysis_id: int
    input_type: str = "text"
    risk_score: int
    risk_level: str
    confidence: float
    extraction: TextExtractionResult
    indicators: List[IndicatorResult]
    structural_hash: Optional[str] = None
    similarity_verdict: Optional[str] = None
    similarity_matches_count: int = 0
    matching_signals: List[str] = Field(default_factory=list)
    campaign_id: Optional[str] = None
    defensive_guidance: List[dict] = Field(default_factory=list)
    ai_investigation_report: Optional[dict] = None
    created_at: datetime

    class Config:
        from_attributes = True

class UrlAnalysisRequest(BaseModel):
    url: str = Field(..., min_length=3, max_length=2048)
    context_text: Optional[str] = None

class UrlAnalysisResponse(BaseModel):
    analysis_id: int
    input_type: str = "url"
    url: str
    risk_score: int
    risk_level: str
    confidence: float
    domain: str
    hostname: str
    tld: str
    indicators: List[IndicatorResult]
    created_at: datetime

    class Config:
        from_attributes = True

class ScreenshotAnalysisResponse(BaseModel):
    analysis_id: int
    input_type: str = "screenshot"
    risk_score: int
    risk_level: str
    confidence: float
    ocr_engine: str
    extracted_text: str
    forensics: dict
    extraction: TextExtractionResult
    indicators: List[IndicatorResult]
    created_at: datetime

    class Config:
        from_attributes = True

class QrAnalysisResponse(BaseModel):
    analysis_id: int
    input_type: str = "qr"
    decoded_payload: Optional[str]
    payload_type: str # "url", "payment", "text", "empty"
    risk_score: int
    risk_level: str
    confidence: float
    indicators: List[IndicatorResult]
    metadata: dict
    created_at: datetime

    class Config:
        from_attributes = True


