from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List

from app.api import deps
from app.models.user import User, Campaign
from app.services.intelligence.campaign_engine import (
    CampaignDetailReport, build_threat_timeline
)

router = APIRouter()

@router.get("/", response_model=List[CampaignDetailReport])
def list_campaigns(
    db: Session = Depends(deps.get_db),
    current_user: User = Depends(deps.get_current_user)
):
    """
    List all detected scam campaigns and active threat clusters.
    """
    campaigns = db.query(Campaign).order_by(Campaign.latest_observed.desc()).all()
    reports = []
    for c in campaigns:
        rep = build_threat_timeline(db, c.campaign_id)
        if rep:
            reports.append(rep)
    return reports

@router.get("/{campaign_id}", response_model=CampaignDetailReport)
def get_campaign_detail(
    campaign_id: str,
    db: Session = Depends(deps.get_db),
    current_user: User = Depends(deps.get_current_user)
):
    """
    Get full threat timeline, members, and indicators for a specific campaign ID.
    """
    report = build_threat_timeline(db, campaign_id)
    if not report:
        raise HTTPException(status_code=404, detail="Campaign not found or insufficient evidence.")
    return report
