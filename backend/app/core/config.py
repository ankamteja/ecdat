"""Runtime configuration.

Every value is environment driven so the same image runs in a demo, in CI and
on an air gapped host without a rebuild. Defaults are chosen so that a fresh
clone starts with no environment file at all.
"""

from __future__ import annotations

from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

REPO_ROOT = Path(__file__).resolve().parents[3]


class Settings(BaseSettings):
    """Application settings, read from the environment or a local .env file."""

    model_config = SettingsConfigDict(env_prefix="ECDAT_", env_file=".env", extra="ignore")

    app_name: str = "ECDAT"
    version: str = "0.1.0"

    # Storage. SQLite by default; point this at PostgreSQL to switch, no code change.
    database_url: str = f"sqlite:///{REPO_ROOT / 'data' / 'ecdat.db'}"

    # Auth. The default secret is deliberately obvious so that shipping it is loud.
    jwt_secret: str = "change-me-in-production"
    jwt_algorithm: str = "HS256"
    jwt_expiry_minutes: int = 720
    seed_admin_user: str = "admin"
    seed_admin_password: str = "ecdat-demo"

    # Scan runner.
    max_workers: int = 4
    scan_timeout_seconds: int = 300
    max_file_bytes: int = 1_000_000

    # Paths.
    knowledge_dir: Path = REPO_ROOT / "backend" / "app" / "knowledge"
    schema_dir: Path = REPO_ROOT / "schemas"
    samples_dir: Path = REPO_ROOT / "samples"
    report_dir: Path = REPO_ROOT / "reports_out"

    @property
    def data_dir(self) -> Path:
        """Where the SQLite file and other writable state live.

        Kept outside the application tree so the container can mount it as the
        only writable location, leaving the code itself read-only.
        """
        return REPO_ROOT / "data"


settings = Settings()
