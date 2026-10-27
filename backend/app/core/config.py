import os
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "ProtectPro AI"
    # Local fallback to SQLite; production uses external PostgreSQL (Neon/Supabase)
    SQLALCHEMY_DATABASE_URI: str = os.getenv("DATABASE_URL", "sqlite:///./protectpro.db")
    SECRET_KEY: str = os.getenv("SECRET_KEY", "super-secret-key-for-local-dev-only")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7 # 7 days
    CORS_ORIGINS: str = os.getenv("CORS_ORIGINS", "*")

    def get_database_url(self) -> str:
        url = self.SQLALCHEMY_DATABASE_URI
        # Cloud providers often output postgres:// which SQLAlchemy 2.0 requires as postgresql://
        if url.startswith("postgres://"):
            url = url.replace("postgres://", "postgresql://", 1)
        return url

settings = Settings()
