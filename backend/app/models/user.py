from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Boolean
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from app.models.base import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    
    analyses = relationship("Analysis", back_populates="owner")

class Analysis(Base):
    __tablename__ = "analyses"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    input_type = Column(String, nullable=False, index=True) # 'text', 'url', 'image'
    risk_score = Column(Integer, default=0, index=True)
    risk_level = Column(String, default="Unknown", index=True) # Low, Medium, High, Critical
    status = Column(String, default="pending") # pending, completed, failed
    created_at = Column(DateTime(timezone=True), server_default=func.now(), index=True)

    owner = relationship("User", back_populates="analyses")
    inputs = relationship("AnalysisInput", back_populates="analysis", cascade="all, delete-orphan")
    indicators = relationship("AnalysisIndicator", back_populates="analysis", cascade="all, delete-orphan")
    fingerprint = relationship("Fingerprint", back_populates="analysis", uselist=False, cascade="all, delete-orphan")

class AnalysisInput(Base):
    __tablename__ = "analysis_inputs"
    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(Integer, ForeignKey("analyses.id"), nullable=False, index=True)
    raw_content = Column(String, nullable=False)
    normalized_content = Column(String, nullable=True)
    
    analysis = relationship("Analysis", back_populates="inputs")

class AnalysisIndicator(Base):
    __tablename__ = "analysis_indicators"
    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(Integer, ForeignKey("analyses.id"), nullable=False, index=True)
    indicator_type = Column(String, nullable=False, index=True) # e.g. 'Urgency', 'Credential Request'
    value = Column(String, nullable=True) # e.g. the matching string
    weight = Column(Integer, default=0) # Risk points
    evidence = Column(String, nullable=True) # explanation for this indicator
    
    analysis = relationship("Analysis", back_populates="indicators")

class Fingerprint(Base):
    __tablename__ = "fingerprints"
    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(Integer, ForeignKey("analyses.id"), nullable=False, unique=True)
    structural_hash = Column(String, index=True, nullable=False)
    extracted_domains = Column(String, nullable=True) # Comma-separated domains
    scam_category = Column(String, index=True, nullable=False) # e.g. 'phishing', 'advance_fee'
    feature_vector = Column(String, nullable=False) # JSON array of normalized numerical vector
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    analysis = relationship("Analysis", back_populates="fingerprint")

class Campaign(Base):
    __tablename__ = "campaigns"
    id = Column(Integer, primary_key=True, index=True)
    campaign_id = Column(String, unique=True, index=True, nullable=False) # e.g. "CP-2026-0042"
    name = Column(String, nullable=False)
    claimed_organization = Column(String, nullable=True)
    primary_domain = Column(String, nullable=True)
    first_observed = Column(DateTime(timezone=True), server_default=func.now())
    latest_observed = Column(DateTime(timezone=True), server_default=func.now())
    status = Column(String, default="active") # active, dormant, resolved

    members = relationship("CampaignMember", back_populates="campaign", cascade="all, delete-orphan")

class CampaignMember(Base):
    __tablename__ = "campaign_members"
    id = Column(Integer, primary_key=True, index=True)
    campaign_id = Column(Integer, ForeignKey("campaigns.id"), nullable=False)
    analysis_id = Column(Integer, ForeignKey("analyses.id"), nullable=False)
    similarity_score = Column(Integer, default=100) # Percentage
    added_at = Column(DateTime(timezone=True), server_default=func.now())

    campaign = relationship("Campaign", back_populates="members")
    analysis = relationship("Analysis")

class ThreatEntity(Base):
    __tablename__ = "threat_entities"
    id = Column(Integer, primary_key=True, index=True)
    entity_type = Column(String, index=True, nullable=False) # "DOMAIN", "URL", "PHONE", "EMAIL", "BRAND", "CATEGORY", "CAMPAIGN"
    value = Column(String, index=True, nullable=False)
    risk_level = Column(String, default="UNKNOWN")
    first_seen = Column(DateTime(timezone=True), server_default=func.now())

class ThreatRelationship(Base):
    __tablename__ = "threat_relationships"
    id = Column(Integer, primary_key=True, index=True)
    analysis_id = Column(Integer, ForeignKey("analyses.id"), nullable=False)
    source_entity_id = Column(Integer, ForeignKey("threat_entities.id"), nullable=False)
    target_entity_id = Column(Integer, ForeignKey("threat_entities.id"), nullable=False)
    relation_type = Column(String, nullable=False) # "TARGETS_BRAND", "USES_DOMAIN", "SENDS_FROM", "PART_OF_CAMPAIGN"
    confidence = Column(Integer, default=90) # 0 to 100
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    source_entity = relationship("ThreatEntity", foreign_keys=[source_entity_id])
    target_entity = relationship("ThreatEntity", foreign_keys=[target_entity_id])
    analysis = relationship("Analysis")

class KnowledgeDocument(Base):
    __tablename__ = "knowledge_documents"
    id = Column(Integer, primary_key=True, index=True)
    doc_id = Column(String, unique=True, index=True, nullable=False) # e.g. "KB-PHISH-001"
    category = Column(String, index=True, nullable=False) # "phishing", "impersonation", "qr_fraud", etc.
    title = Column(String, nullable=False)
    content = Column(String, nullable=False)
    recommended_mitigation = Column(String, nullable=False)
    keywords = Column(String, nullable=False) # comma-separated search terms
    created_at = Column(DateTime(timezone=True), server_default=func.now())
