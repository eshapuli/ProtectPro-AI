from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1 import auth, history, analyses, campaigns, evaluation
from app.db.database import engine
from app.models.base import Base
# Import all models to ensure they are registered with Base
from app.models import user

# Create tables for SQLite (In production, use Alembic migrations instead)
Base.metadata.create_all(bind=engine)

from app.core.rate_limiter import RateLimitMiddleware

from app.core.config import settings

app = FastAPI(title="ProtectPro AI API")

app.add_middleware(RateLimitMiddleware, max_requests=100, window_seconds=60)

cors_origins = [o.strip() for o in settings.CORS_ORIGINS.split(",") if o.strip()]
if not cors_origins or "*" in cors_origins:
    cors_origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=False if cors_origins == ["*"] else True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix="/api/v1/auth", tags=["auth"])
app.include_router(history.router, prefix="/api/v1/history", tags=["history"])
app.include_router(analyses.router, prefix="/api/v1/analyses", tags=["analyses"])
app.include_router(campaigns.router, prefix="/api/v1/campaigns", tags=["campaigns"])
app.include_router(evaluation.router, prefix="/api/v1/evaluation", tags=["evaluation"])

@app.get("/")
def root():
    return {"message": "ProtectPro AI API is running"}
