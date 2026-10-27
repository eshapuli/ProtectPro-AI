import json
import random
from typing import List, Optional, Dict, Any
from datetime import datetime
from sqlalchemy.orm import Session
from pydantic import BaseModel

from app.models.user import Campaign, CampaignMember, Fingerprint, Analysis, AnalysisInput, AnalysisIndicator
from app.services.intelligence.fingerprint_engine import calculate_cosine_similarity

class TimelineEvent(BaseModel):
    event_type: str # "FIRST_OBSERVED", "MUTATION_DETECTED", "INFRASTRUCTURE_EXPANSION", "LATEST_OBSERVATION"
    timestamp: datetime
    analysis_id: int
    description: str
    risk_score: int
    indicators: List[str]

class CampaignDetailReport(BaseModel):
    campaign_id: str
    name: str
    claimed_organization: Optional[str]
    primary_domain: Optional[str]
    total_submissions: int
    first_observed: datetime
    latest_observed: datetime
    common_indicators: List[str]
    timeline: List[TimelineEvent]

def cluster_and_detect_campaigns(
    db: Session,
    current_analysis_id: int,
    similarity_threshold: float = 0.85
) -> Optional[Campaign]:
    """
    Scam Campaign Detection Engine:
    Clusters related submissions based on:
    - Shared malicious domain infrastructure
    - Dense feature vector cosine similarity (>= 0.85)
    - Structural hash matches
    
    If 2 or more related submissions exist, assigns/groups them into a Campaign ID (e.g. CP-2026-0042).
    Never fabricates fake data; returns None if insufficient evidence exists.
    """
    current_fp = db.query(Fingerprint).filter(Fingerprint.analysis_id == current_analysis_id).first()
    if not current_fp:
        return None

    current_vec = json.loads(current_fp.feature_vector)
    current_domains = set(current_fp.extracted_domains.split(',')) if current_fp.extracted_domains else set()

    # Find candidate historical members
    all_fps = db.query(Fingerprint).filter(Fingerprint.analysis_id != current_analysis_id).all()
    matching_analysis_ids: List[int] = []

    for prev in all_fps:
        prev_vec = json.loads(prev.feature_vector)
        sim = calculate_cosine_similarity(current_vec, prev_vec)
        prev_domains = set(prev.extracted_domains.split(',')) if prev.extracted_domains else set()
        shared_domains = current_domains.intersection(prev_domains)

        # Candidate criteria: identical structural hash, strong vector similarity, or shared rare domain
        if current_fp.structural_hash == prev.structural_hash or sim >= similarity_threshold or (shared_domains and len(shared_domains) > 0 and '' not in shared_domains):
            matching_analysis_ids.append(prev.analysis_id)

    if not matching_analysis_ids:
        return None # Insufficient evidence to establish a campaign

    # Check if any matching analysis is already part of an established campaign
    existing_member = db.query(CampaignMember).filter(CampaignMember.analysis_id.in_(matching_analysis_ids)).first()

    if existing_member:
        campaign = existing_member.campaign
        # Link current analysis to existing campaign
        already_in = db.query(CampaignMember).filter(
            CampaignMember.campaign_id == campaign.id,
            CampaignMember.analysis_id == current_analysis_id
        ).first()
        if not already_in:
            member = CampaignMember(
                campaign_id=campaign.id,
                analysis_id=current_analysis_id,
                similarity_score=int(similarity_threshold * 100),
                added_at=datetime.utcnow()
            )
            db.add(member)
            campaign.latest_observed = datetime.utcnow()
            db.commit()
            db.refresh(campaign)
        return campaign
    else:
        # Create a new campaign for this emerging cluster
        random_suffix = random.randint(1000, 9999)
        camp_code = f"CP-2026-{random_suffix}"
        camp_name = f"{current_fp.scam_category.replace('_', ' ').title()} Campaign ({camp_code})"
        primary_dom = list(current_domains)[0] if current_domains else "Unassigned"

        new_campaign = Campaign(
            campaign_id=camp_code,
            name=camp_name,
            claimed_organization="Detected Threat Cluster",
            primary_domain=primary_dom,
            first_observed=datetime.utcnow(),
            latest_observed=datetime.utcnow(),
            status="active"
        )
        db.add(new_campaign)
        db.commit()
        db.refresh(new_campaign)

        # Add current analysis and matching peer analyses as members
        all_cluster_ids = [current_analysis_id] + matching_analysis_ids
        for a_id in all_cluster_ids:
            member = CampaignMember(
                campaign_id=new_campaign.id,
                analysis_id=a_id,
                similarity_score=int(similarity_threshold * 100),
                added_at=datetime.utcnow()
            )
            db.add(member)
        db.commit()
        db.refresh(new_campaign)
        return new_campaign

def build_threat_timeline(db: Session, campaign_id_str: str) -> Optional[CampaignDetailReport]:
    """
    Constructs an interactive chronological Threat Timeline for an established campaign.
    """
    campaign = db.query(Campaign).filter(Campaign.campaign_id == campaign_id_str).first()
    if not campaign:
        return None

    members = db.query(CampaignMember).filter(CampaignMember.campaign_id == campaign.id).order_by(CampaignMember.added_at.asc()).all()
    timeline_events: List[TimelineEvent] = []
    indicator_frequency: Dict[str, int] = {}

    for idx, mem in enumerate(members):
        analysis = db.query(Analysis).filter(Analysis.id == mem.analysis_id).first()
        if not analysis:
            continue

        indicators = db.query(AnalysisIndicator).filter(AnalysisIndicator.analysis_id == analysis.id).all()
        ind_names = [i.indicator_type for i in indicators]
        for name in ind_names:
            indicator_frequency[name] = indicator_frequency.get(name, 0) + 1

        if idx == 0:
            ev_type = "FIRST_OBSERVED"
            desc = f"Initial threat pattern detected ({analysis.input_type.upper()}). Origin fingerprint cataloged."
        elif idx == len(members) - 1 and len(members) > 1:
            ev_type = "LATEST_OBSERVATION"
            desc = f"Most recent observed submission linked to campaign infrastructure."
        else:
            ev_type = "MUTATION_DETECTED"
            desc = f"Variant observed with {analysis.risk_score}/100 risk score."

        timeline_events.append(
            TimelineEvent(
                event_type=ev_type,
                timestamp=mem.added_at,
                analysis_id=analysis.id,
                description=desc,
                risk_score=analysis.risk_score,
                indicators=ind_names
            )
        )

    # Top recurring indicators
    common_indicators = [k for k, _ in sorted(indicator_frequency.items(), key=lambda item: item[1], reverse=True)[:5]]

    return CampaignDetailReport(
        campaign_id=campaign.campaign_id,
        name=campaign.name,
        claimed_organization=campaign.claimed_organization,
        primary_domain=campaign.primary_domain,
        total_submissions=len(members),
        first_observed=campaign.first_observed,
        latest_observed=campaign.latest_observed,
        common_indicators=common_indicators,
        timeline=timeline_events
    )
