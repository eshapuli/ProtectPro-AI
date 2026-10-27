from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.core.config import settings

# Note: check_same_thread is required for SQLite in FastAPI
db_url = settings.get_database_url()
engine = create_engine(
    db_url, connect_args={"check_same_thread": False} if "sqlite" in db_url else {}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
