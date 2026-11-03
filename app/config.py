"""Runtime configuration, read once from environment variables."""

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    db_path: str = os.getenv("AUDIT_DB_PATH", "audit.db")
    retention_days: float = float(os.getenv("AUDIT_RETENTION_DAYS", "365"))
    admin_key: str | None = os.getenv("AUDIT_ADMIN_KEY") or None  # unset = admin ops open (dev)


settings = Settings()
