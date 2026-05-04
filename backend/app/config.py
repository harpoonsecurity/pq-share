from pathlib import Path
from pydantic_settings import BaseSettings, SettingsConfigDict


PROJECT_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="PQSHARE_", env_file=".env", extra="ignore")

    db_path: Path = PROJECT_ROOT / "data" / "pqshare.db"
    blob_dir: Path = PROJECT_ROOT / "data" / "blobs"
    frontend_dir: Path = PROJECT_ROOT / "frontend"

    base_url: str = "http://127.0.0.1:8000"
    session_secret: str = "dev-only-replace-me"
    session_ttl_hours: int = 24

    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_user: str | None = None
    smtp_password: str | None = None
    smtp_use_starttls: bool = True
    smtp_from: str = "pqshare@localhost"
    smtp_from_name: str = "pq-share"


settings = Settings()
settings.blob_dir.mkdir(parents=True, exist_ok=True)
settings.db_path.parent.mkdir(parents=True, exist_ok=True)
