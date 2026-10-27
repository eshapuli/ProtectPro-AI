from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session
from typing import Optional, List
from datetime import datetime
from pydantic import BaseModel

from app.api import deps
from app.models.user import Analysis, User

router = APIRouter()

class AnalysisSummaryItem(BaseModel):
    id: int
    input_type: str
    risk_score: int
    risk_level: str
    status: str
    created_at: datetime

    class Config:
        from_attributes = True

class HistoryResponse(BaseModel):
    total_count: int
    high_risk_count: int
    safe_count: int
    average_risk: float
    page: int
    page_size: int
    analyses: List[AnalysisSummaryItem]

@router.get("/", response_model=HistoryResponse)
def get_history(
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    risk_filter: Optional[str] = Query(None),
    db: Session = Depends(deps.get_db),
    current_user: User = Depends(deps.get_current_user)
):
    """
    Get paginated analysis history and aggregated metrics with tenant isolation.
    """
    base_query = db.query(Analysis).filter(Analysis.user_id == current_user.id)
    total_count = base_query.count()
    
    # Fast metric aggregations
    high_risk_count = base_query.filter(Analysis.risk_score >= 55).count()
    safe_count = base_query.filter(Analysis.risk_score < 30).count()
    
    all_scores = [a.risk_score for a in base_query.all()]
    avg_risk = round(sum(all_scores) / len(all_scores), 1) if all_scores else 0.0

    filtered_query = base_query
    if risk_filter:
        filtered_query = filtered_query.filter(Analysis.risk_level == risk_filter)

    items = filtered_query.order_by(Analysis.created_at.desc()).offset(skip).limit(limit).all()

    return HistoryResponse(
        total_count=total_count,
        high_risk_count=high_risk_count,
        safe_count=safe_count,
        average_risk=avg_risk,
        page=(skip // limit) + 1,
        page_size=limit,
        analyses=items
    )
