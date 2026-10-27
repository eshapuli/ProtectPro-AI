from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from sqlalchemy.orm import Session
from datetime import datetime
from typing import List

from app.api import deps
from app.models.user import User, Analysis, AnalysisInput, AnalysisIndicator
from app.schemas.analysis import (
    TextAnalysisRequest, TextAnalysisResponse, TextExtractionResult, IndicatorResult,
    UrlAnalysisRequest, UrlAnalysisResponse, ScreenshotAnalysisResponse, QrAnalysisResponse
)
from app.services.extractors.text_extractor import extract_entities_from_text
from app.services.extractors.ocr_extractor import run_ocr_on_image
from app.services.extractors.qr_extractor import decode_qr_image, analyze_qr_payload
from app.services.analyzers.rule_engine import analyze_text_rules
from app.services.analyzers.url_dna_analyzer import analyze_url_dna
from app.services.risk.risk_engine import calculate_risk_score
from app.services.intelligence.similarity_engine import (
    create_and_store_fingerprint, search_similar_fingerprints, SimilaritySearchReport
)
from app.services.intelligence.campaign_engine import cluster_and_detect_campaigns
from app.services.intelligence.threat_graph import (
    extract_and_record_threat_graph, build_threat_graph_data, ThreatGraphResponse
)
from app.services.intelligence.rag_knowledge_base import (
    query_rag_knowledge_base, seed_knowledge_base_if_needed, KnowledgeItem
)
from app.services.ai.investigation_agent import ControlledInvestigationAgent
from app.core.input_security import sanitize_untrusted_input

router = APIRouter()

@router.post("/text", response_model=TextAnalysisResponse)
def analyze_text(
    payload: TextAnalysisRequest,
    db: Session = Depends(deps.get_db),
    current_user: User = Depends(deps.get_current_user)
):
    """
    Analyzes submitted text for scam, phishing, and fraudulent indicators.
    Pipeline: Input -> Normalization & Extraction -> Rule Analysis -> Risk Engine -> DB Persistence
    """
    raw_text = payload.text.strip()
    if not raw_text:
        raise HTTPException(status_code=400, detail="Submission text cannot be empty.")
        
    # Input Security & Sanitization
    sanitized_text, was_injection = sanitize_untrusted_input(raw_text)
        
    # 1. Extraction & Normalization
    extraction = extract_entities_from_text(sanitized_text)
    
    # 2. Rule & Heuristic Analysis
    indicators = analyze_text_rules(extraction)
    
    # 3. Deterministic Risk Scoring
    risk_assessment = calculate_risk_score(indicators)
    
    # 4. Database Persistence
    db_analysis = Analysis(
        user_id=current_user.id,
        input_type="text",
        risk_score=risk_assessment.score,
        risk_level=risk_assessment.risk_level,
        status="completed",
        created_at=datetime.utcnow()
    )
    db.add(db_analysis)
    db.commit()
    db.refresh(db_analysis)
    
    # Save raw and normalized inputs
    db_input = AnalysisInput(
        analysis_id=db_analysis.id,
        raw_content=extraction.raw_text,
        normalized_content=extraction.normalized_text
    )
    db.add(db_input)
    
    # Save individual evidence indicators
    for ind in indicators:
        db_indicator = AnalysisIndicator(
            analysis_id=db_analysis.id,
            indicator_type=ind.indicator_type,
            value=ind.value,
            weight=ind.weight,
            evidence=ind.evidence
        )
        db.add(db_indicator)
        
    db.commit()
    
    # 5. Scam Fingerprinting & "Have I Seen This Before?" Similarity Engine
    indicator_types = [ind.indicator_type for ind in indicators]
    extracted_domains = [url.split('/')[2] if '://' in url else url.split('/')[0] for url in extraction.extracted_urls]
    
    similarity_report = search_similar_fingerprints(
        db=db,
        current_analysis_id=db_analysis.id,
        text=extraction.normalized_text,
        indicator_types=indicator_types,
        domains=extracted_domains,
        user_id=current_user.id
    )
    
    fp = create_and_store_fingerprint(
        db=db,
        analysis_id=db_analysis.id,
        text=extraction.normalized_text,
        indicator_types=indicator_types,
        domains=extracted_domains
    )
    
    # 6. Scam Campaign Detection & Clustering
    detected_campaign = cluster_and_detect_campaigns(
        db=db,
        current_analysis_id=db_analysis.id,
        similarity_threshold=0.85
    )
    campaign_id_str = detected_campaign.campaign_id if detected_campaign else None
    
    # 7. Threat Relationship Graph Extraction
    extract_and_record_threat_graph(db, db_analysis.id)
    
    # 8. RAG Defensive Knowledge Base Retrieval
    defensive_docs = query_rag_knowledge_base(db, extraction.normalized_text, limit=2)
    guidance_list = [d.model_dump() for d in defensive_docs]

    # 9. Controlled AI Investigation Agent
    agent = ControlledInvestigationAgent(db=db)
    agent_report = agent.generate_investigation_report(
        raw_text=extraction.raw_text,
        risk_result=risk_assessment,
        indicators=indicators,
        campaign_id=campaign_id_str,
        similarity_verdict=similarity_report.verdict
    )

    unique_matching_signals = []
    for m in similarity_report.matches:
        for sig in m.matching_signals:
            if sig not in unique_matching_signals:
                unique_matching_signals.append(sig)

    return TextAnalysisResponse(
        analysis_id=db_analysis.id,
        input_type="text",
        risk_score=risk_assessment.score,
        risk_level=risk_assessment.risk_level,
        confidence=risk_assessment.confidence,
        extraction=extraction,
        indicators=indicators,
        structural_hash=fp.structural_hash,
        similarity_verdict=similarity_report.verdict,
        similarity_matches_count=similarity_report.total_historical_matches,
        matching_signals=unique_matching_signals,
        campaign_id=campaign_id_str,
        defensive_guidance=guidance_list,
        ai_investigation_report=agent_report.model_dump(),
        created_at=db_analysis.created_at
    )

@router.post("/url", response_model=UrlAnalysisResponse)
def analyze_url(
    payload: UrlAnalysisRequest,
    db: Session = Depends(deps.get_db),
    current_user: User = Depends(deps.get_current_user)
):
    """
    Analyzes submitted URL for brand spoofing, deceptive subdomains, risky TLDs, and phishing patterns.
    Safe passive inspection: Does NOT navigate or download remote executable content.
    """
    raw_url = payload.url.strip()
    if not raw_url:
        raise HTTPException(status_code=400, detail="URL cannot be empty.")

    # 1. Passive URL DNA Analysis
    report = analyze_url_dna(raw_url, context_text=payload.context_text)

    # 2. Evidence-Based Deterministic Risk Scoring
    risk_assessment = calculate_risk_score(report.indicators)

    # 3. Database Persistence
    db_analysis = Analysis(
        user_id=current_user.id,
        input_type="url",
        risk_score=risk_assessment.score,
        risk_level=risk_assessment.risk_level,
        status="completed",
        created_at=datetime.utcnow()
    )
    db.add(db_analysis)
    db.commit()
    db.refresh(db_analysis)

    db_input = AnalysisInput(
        analysis_id=db_analysis.id,
        raw_content=raw_url,
        normalized_content=f"{report.scheme}://{report.hostname}{report.path}"
    )
    db.add(db_input)

    for ind in report.indicators:
        db_indicator = AnalysisIndicator(
            analysis_id=db_analysis.id,
            indicator_type=ind.indicator_type,
            value=ind.value,
            weight=ind.weight,
            evidence=ind.evidence
        )
        db.add(db_indicator)

    db.commit()

    return UrlAnalysisResponse(
        analysis_id=db_analysis.id,
        input_type="url",
        url=report.raw_url,
        risk_score=risk_assessment.score,
        risk_level=risk_assessment.risk_level,
        confidence=risk_assessment.confidence,
        domain=report.domain,
        hostname=report.hostname,
        tld=report.tld,
        indicators=report.indicators,
        created_at=db_analysis.created_at
    )

@router.post("/screenshot", response_model=ScreenshotAnalysisResponse)
async def analyze_screenshot(
    file: UploadFile = File(...),
    db: Session = Depends(deps.get_db),
    current_user: User = Depends(deps.get_current_user)
):
    """
    Analyzes uploaded screenshot:
    - Safe file validation & size limit (max 5MB)
    - Image forensics (dimensions, color mode, aspect ratio)
    - OCR extraction (pytesseract/easyocr)
    - Multimodal pipeline: OCR text -> Entity Extraction -> URL DNA -> Rule Analysis -> Risk Engine
    """
    # 1. Safe File Validation
    if not file.content_type or not file.content_type.startswith("image/"):
        raise HTTPException(status_code=400, detail="Only image files (PNG, JPG, JPEG, WEBP) are accepted.")
        
    image_bytes = await file.read()
    if len(image_bytes) > 5 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="Image file exceeds maximum allowable size (5MB).")

    # 2. Forensic Inspection and OCR
    try:
        extracted_text, forensics, ocr_engine = run_ocr_on_image(image_bytes)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Image processing failed: Unable to parse image file.")

    # 3. Entity & Adversarial Text Extraction
    extraction = extract_entities_from_text(extracted_text)

    # 4. Multi-modal Technical Signal Collection
    indicators = []
    
    # Check text rules
    text_indicators = analyze_text_rules(extraction)
    indicators.extend(text_indicators)
    
    # Check any extracted URLs with URL DNA
    for url in extraction.extracted_urls:
        url_report = analyze_url_dna(url, context_text=extracted_text)
        indicators.extend(url_report.indicators)

    # Add forensic indicator if no text was found or very low resolution
    if not extracted_text:
        indicators.append(
            IndicatorResult(
                indicator_type="Visual Forensics Notice",
                value="No readable text detected",
                weight=0,
                evidence=f"Image resolution {forensics.get('width')}x{forensics.get('height')}. No textual scam indicators could be parsed via OCR."
            )
        )

    # 5. Deterministic Evidence Risk Scoring
    risk_assessment = calculate_risk_score(indicators)

    # 6. Database Persistence
    db_analysis = Analysis(
        user_id=current_user.id,
        input_type="screenshot",
        risk_score=risk_assessment.score,
        risk_level=risk_assessment.risk_level,
        status="completed",
        created_at=datetime.utcnow()
    )
    db.add(db_analysis)
    db.commit()
    db.refresh(db_analysis)

    db_input = AnalysisInput(
        analysis_id=db_analysis.id,
        raw_content=f"[Screenshot: {file.filename or 'upload.png'}] {extracted_text}",
        normalized_content=extraction.normalized_text
    )
    db.add(db_input)

    for ind in indicators:
        db_indicator = AnalysisIndicator(
            analysis_id=db_analysis.id,
            indicator_type=ind.indicator_type,
            value=ind.value,
            weight=ind.weight,
            evidence=ind.evidence
        )
        db.add(db_indicator)

    db.commit()

    return ScreenshotAnalysisResponse(
        analysis_id=db_analysis.id,
        input_type="screenshot",
        risk_score=risk_assessment.score,
        risk_level=risk_assessment.risk_level,
        confidence=risk_assessment.confidence,
        ocr_engine=ocr_engine,
        extracted_text=extracted_text,
        forensics=forensics,
        extraction=extraction,
        indicators=indicators,
        created_at=db_analysis.created_at
    )

@router.post("/qr", response_model=QrAnalysisResponse)
async def analyze_qr(
    file: UploadFile = File(...),
    db: Session = Depends(deps.get_db),
    current_user: User = Depends(deps.get_current_user)
):
    """
    Safely analyzes an uploaded QR code image:
    - Decodes QR payload using computer vision (OpenCV) in-memory
    - Never navigates or executes the target destination
    - Detects quishing (QR phishing), deceptive payment schemes, and app downloads
    - Integrates URL DNA analysis when payload contains links
    - Deterministic risk scoring
    """
    if not file.content_type or not file.content_type.startswith("image/"):
        raise HTTPException(status_code=400, detail="Only image files (PNG, JPG, JPEG, WEBP) are accepted.")

    image_bytes = await file.read()
    if len(image_bytes) > 5 * 1024 * 1024:
        raise HTTPException(status_code=400, detail="QR image file exceeds maximum allowable size (5MB).")

    decoded_payload, metadata = decode_qr_image(image_bytes)
    indicators: List[IndicatorResult] = []
    payload_type = "empty"

    if not decoded_payload:
        indicators.append(
            IndicatorResult(
                indicator_type="QR Matrix Not Decoded",
                value="No matrix pattern detected",
                weight=0,
                evidence="Unable to find or decode a valid QR matrix code in the submitted image."
            )
        )
    else:
        # Determine payload type & run security inspections
        qr_indicators = analyze_qr_payload(decoded_payload)
        indicators.extend(qr_indicators)

        if decoded_payload.startswith(("http://", "https://", "www.")):
            payload_type = "url"
            url_report = analyze_url_dna(decoded_payload)
            indicators.extend(url_report.indicators)
        elif any(decoded_payload.lower().startswith(p) for p in ["bitcoin:", "ethereum:", "upi:", "solana:"]):
            payload_type = "payment"
        else:
            payload_type = "text"
            # Extract and check text rules
            extraction = extract_entities_from_text(decoded_payload)
            text_indicators = analyze_text_rules(extraction)
            indicators.extend(text_indicators)

    # Deterministic Risk Scoring
    risk_assessment = calculate_risk_score(indicators)

    # Database Persistence
    db_analysis = Analysis(
        user_id=current_user.id,
        input_type="qr",
        risk_score=risk_assessment.score,
        risk_level=risk_assessment.risk_level,
        status="completed",
        created_at=datetime.utcnow()
    )
    db.add(db_analysis)
    db.commit()
    db.refresh(db_analysis)

    db_input = AnalysisInput(
        analysis_id=db_analysis.id,
        raw_content=f"[QR Image: {file.filename or 'qr.png'}] Decoded: {decoded_payload or 'None'}",
        normalized_content=decoded_payload or ""
    )
    db.add(db_input)

    for ind in indicators:
        db_indicator = AnalysisIndicator(
            analysis_id=db_analysis.id,
            indicator_type=ind.indicator_type,
            value=ind.value,
            weight=ind.weight,
            evidence=ind.evidence
        )
        db.add(db_indicator)

    db.commit()

    return QrAnalysisResponse(
        analysis_id=db_analysis.id,
        input_type="qr",
        decoded_payload=decoded_payload,
        payload_type=payload_type,
        risk_score=risk_assessment.score,
        risk_level=risk_assessment.risk_level,
        confidence=risk_assessment.confidence,
        indicators=indicators,
        metadata=metadata,
        created_at=db_analysis.created_at
    )

@router.get("/{analysis_id}", response_model=TextAnalysisResponse)
def get_analysis_by_id(
    analysis_id: int,
    db: Session = Depends(deps.get_db),
    current_user: User = Depends(deps.get_current_user)
):
    """
    Retrieve full details for a previously run analysis with tenant isolation.
    """
    analysis = db.query(Analysis).filter(
        Analysis.id == analysis_id,
        Analysis.user_id == current_user.id
    ).first()
    
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis record not found.")
        
    # Load input
    db_input = db.query(AnalysisInput).filter(AnalysisInput.analysis_id == analysis.id).first()
    raw_text = db_input.raw_content if db_input else ""
    extraction = extract_entities_from_text(raw_text)
    
    # Load indicators
    db_indicators = db.query(AnalysisIndicator).filter(AnalysisIndicator.analysis_id == analysis.id).all()
    indicators = [
        IndicatorResult(
            indicator_type=ind.indicator_type,
            value=ind.value,
            weight=ind.weight,
            evidence=ind.evidence or ""
        )
        for ind in db_indicators
    ]
    
    # Confidence estimation based on signals
    distinct_types = len(set(ind.indicator_type for ind in indicators))
    confidence = min(0.60 + (distinct_types * 0.10), 0.98) if indicators else 0.85
    
    return TextAnalysisResponse(
        analysis_id=analysis.id,
        input_type=analysis.input_type,
        risk_score=analysis.risk_score,
        risk_level=analysis.risk_level,
        confidence=round(confidence, 2),
        extraction=extraction,
        indicators=indicators,
        created_at=analysis.created_at
    )

@router.get("/{analysis_id}/similar", response_model=SimilaritySearchReport)
def get_similar_matches(
    analysis_id: int,
    db: Session = Depends(deps.get_db),
    current_user: User = Depends(deps.get_current_user)
):
    """
    Retrieves historical matches and campaign indicators for a specific analysis.
    """
    analysis = db.query(Analysis).filter(
        Analysis.id == analysis_id,
        Analysis.user_id == current_user.id
    ).first()
    
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis record not found.")

    db_input = db.query(AnalysisInput).filter(AnalysisInput.analysis_id == analysis.id).first()
    raw_text = db_input.normalized_content or db_input.raw_content if db_input else ""
    
    db_indicators = db.query(AnalysisIndicator).filter(AnalysisIndicator.analysis_id == analysis.id).all()
    indicator_types = [ind.indicator_type for ind in db_indicators]

    extraction = extract_entities_from_text(raw_text)
    extracted_domains = [url.split('/')[2] if '://' in url else url.split('/')[0] for url in extraction.extracted_urls]

    report = search_similar_fingerprints(
        db=db,
        current_analysis_id=analysis.id,
        text=raw_text,
        indicator_types=indicator_types,
        domains=extracted_domains,
        user_id=current_user.id
    )
    return report

@router.get("/{analysis_id}/graph", response_model=ThreatGraphResponse)
def get_analysis_threat_graph(
    analysis_id: int,
    db: Session = Depends(deps.get_db),
    current_user: User = Depends(deps.get_current_user)
):
    """
    Get interactive Node-Link graph for a specific analysis record.
    Returns nodes (Entities, Brands, Domains, URLs) and edges (Relationships).
    """
    analysis = db.query(Analysis).filter(
        Analysis.id == analysis_id,
        Analysis.user_id == current_user.id
    ).first()
    
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis record not found.")

    return build_threat_graph_data(db, analysis_id=analysis.id)

@router.get("/graph/network", response_model=ThreatGraphResponse)
def get_global_threat_graph(
    db: Session = Depends(deps.get_db),
    current_user: User = Depends(deps.get_current_user)
):
    """
    Get aggregated threat network graph across historical investigations.
    """
    return build_threat_graph_data(db, analysis_id=None)

@router.get("/{analysis_id}/guidance", response_model=List[KnowledgeItem])
def get_analysis_defensive_guidance(
    analysis_id: int,
    db: Session = Depends(deps.get_db),
    current_user: User = Depends(deps.get_current_user)
):
    """
    Retrieves defensive mitigation playbooks and knowledge articles for an analysis.
    """
    analysis = db.query(Analysis).filter(
        Analysis.id == analysis_id,
        Analysis.user_id == current_user.id
    ).first()
    
    if not analysis:
        raise HTTPException(status_code=404, detail="Analysis record not found.")

    db_input = db.query(AnalysisInput).filter(AnalysisInput.analysis_id == analysis.id).first()
    content = db_input.normalized_content or db_input.raw_content if db_input else ""
    return query_rag_knowledge_base(db, content, limit=3)
