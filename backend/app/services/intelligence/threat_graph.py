from typing import List, Dict, Any, Optional
from pydantic import BaseModel
from sqlalchemy.orm import Session
from datetime import datetime

from app.models.user import (
    ThreatEntity, ThreatRelationship, Analysis, AnalysisInput, AnalysisIndicator, CampaignMember
)
from app.services.extractors.text_extractor import extract_entities_from_text
from app.services.analyzers.brand_registry import lookup_claimed_brand

class GraphNode(BaseModel):
    id: str # e.g. "entity-1" or "analysis-5"
    label: str
    type: str # "ANALYSIS", "DOMAIN", "URL", "BRAND", "PHONE", "EMAIL", "CAMPAIGN"
    risk_level: str
    properties: Dict[str, Any]

class GraphEdge(BaseModel):
    id: str # e.g. "e-1-2"
    source: str
    target: str
    label: str # "CONTAINS_URL", "USES_DOMAIN", "TARGETS_BRAND", "PART_OF_CAMPAIGN"
    confidence: int

class ThreatGraphResponse(BaseModel):
    nodes: List[GraphNode]
    edges: List[GraphEdge]
    total_nodes: int
    total_edges: int

def get_or_create_entity(db: Session, entity_type: str, value: str, risk_level: str = "UNKNOWN") -> ThreatEntity:
    ent = db.query(ThreatEntity).filter(
        ThreatEntity.entity_type == entity_type,
        ThreatEntity.value == value
    ).first()
    if not ent:
        ent = ThreatEntity(
            entity_type=entity_type,
            value=value,
            risk_level=risk_level,
            first_seen=datetime.utcnow()
        )
        db.add(ent)
        db.commit()
        db.refresh(ent)
    return ent

def extract_and_record_threat_graph(db: Session, analysis_id: int):
    """
    Builds and persists threat entities and relationships for an analysis record.
    Connects: Analysis -> Domains -> URLs -> Claimed Brands -> Campaigns.
    """
    analysis = db.query(Analysis).filter(Analysis.id == analysis_id).first()
    if not analysis:
        return

    db_input = db.query(AnalysisInput).filter(AnalysisInput.analysis_id == analysis.id).first()
    content = db_input.normalized_content or db_input.raw_content if db_input else ""
    
    extraction = extract_entities_from_text(content)
    
    # 1. Create Analysis Node Entity
    analysis_ent = get_or_create_entity(
        db, "ANALYSIS", f"Analysis #{analysis.id} ({analysis.input_type.upper()})", analysis.risk_level
    )

    # 2. Check for Claimed Brand
    claimed = lookup_claimed_brand(content)
    if claimed:
        brand_ent = get_or_create_entity(db, "BRAND", claimed.brand_name, "SAFE_TARGET")
        rel = ThreatRelationship(
            analysis_id=analysis.id,
            source_entity_id=analysis_ent.id,
            target_entity_id=brand_ent.id,
            relation_type="CLAIMS_BRAND_IDENTITY",
            confidence=95
        )
        db.add(rel)

    # 3. Process Extracted URLs and Domains
    for url in extraction.extracted_urls:
        url_ent = get_or_create_entity(db, "URL", url, analysis.risk_level)
        rel_url = ThreatRelationship(
            analysis_id=analysis.id,
            source_entity_id=analysis_ent.id,
            target_entity_id=url_ent.id,
            relation_type="CONTAINS_URL",
            confidence=100
        )
        db.add(rel_url)

        # Extract domain
        clean_url = url.split("://")[-1].split("/")[0]
        if clean_url:
            domain_ent = get_or_create_entity(db, "DOMAIN", clean_url, analysis.risk_level)
            rel_dom = ThreatRelationship(
                analysis_id=analysis.id,
                source_entity_id=url_ent.id,
                target_entity_id=domain_ent.id,
                relation_type="HOSTED_ON_DOMAIN",
                confidence=100
            )
            db.add(rel_dom)

    # 4. Process Phones and Emails
    for phone in extraction.extracted_phones:
        phone_ent = get_or_create_entity(db, "PHONE", phone, analysis.risk_level)
        db.add(ThreatRelationship(
            analysis_id=analysis.id,
            source_entity_id=analysis_ent.id,
            target_entity_id=phone_ent.id,
            relation_type="CONTACT_PHONE",
            confidence=90
        ))

    for email in extraction.extracted_emails:
        email_ent = get_or_create_entity(db, "EMAIL", email, analysis.risk_level)
        db.add(ThreatRelationship(
            analysis_id=analysis.id,
            source_entity_id=analysis_ent.id,
            target_entity_id=email_ent.id,
            relation_type="CONTACT_EMAIL",
            confidence=95
        ))

    # 5. Connect Campaign if member
    camp_member = db.query(CampaignMember).filter(CampaignMember.analysis_id == analysis.id).first()
    if camp_member:
        camp = camp_member.campaign
        camp_ent = get_or_create_entity(db, "CAMPAIGN", camp.campaign_id, "HIGH_RISK")
        db.add(ThreatRelationship(
            analysis_id=analysis.id,
            source_entity_id=analysis_ent.id,
            target_entity_id=camp_ent.id,
            relation_type="PART_OF_CAMPAIGN",
            confidence=camp_member.similarity_score
        ))

    db.commit()

def build_threat_graph_data(db: Session, analysis_id: Optional[int] = None) -> ThreatGraphResponse:
    """
    Constructs an interactive Node-Link graph suitable for React Flow or D3 visualizer.
    Can be scoped to a single analysis record or the entire intelligence network.
    """
    query = db.query(ThreatRelationship)
    if analysis_id:
        query = query.filter(ThreatRelationship.analysis_id == analysis_id)
        
    relationships = query.all()
    
    nodes_map: Dict[int, GraphNode] = {}
    edges: List[GraphEdge] = []
    
    for r in relationships:
        src = r.source_entity
        tgt = r.target_entity
        
        if src.id not in nodes_map:
            nodes_map[src.id] = GraphNode(
                id=f"node-{src.id}",
                label=src.value,
                type=src.entity_type,
                risk_level=src.risk_level,
                properties={"db_id": src.id}
            )
        if tgt.id not in nodes_map:
            nodes_map[tgt.id] = GraphNode(
                id=f"node-{tgt.id}",
                label=tgt.value,
                type=tgt.entity_type,
                risk_level=tgt.risk_level,
                properties={"db_id": tgt.id}
            )
            
        edges.append(
            GraphEdge(
                id=f"edge-{r.id}",
                source=f"node-{src.id}",
                target=f"node-{tgt.id}",
                label=r.relation_type,
                confidence=r.confidence
            )
        )
        
    nodes_list = list(nodes_map.values())
    return ThreatGraphResponse(
        nodes=nodes_list,
        edges=edges,
        total_nodes=len(nodes_list),
        total_edges=len(edges)
    )
