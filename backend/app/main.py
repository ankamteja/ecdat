"""ECDAT application entry point.

Enterprise Cryptographic Discovery and Analysis Tool. Discovers cryptographic
usage across source code, TLS endpoints and X.509 certificates, scores each
finding on independent classical and quantum axes, and reports post quantum
migration readiness against the NIST IR 8547 timeline.

Run locally::

    cd backend && uvicorn app.main:app --reload

Then open http://127.0.0.1:8000 for the dashboard, or /docs for the API.
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.api.v1 import auth, findings, misc, reports, scans
from app.core.config import settings
from app.core.db import SessionLocal, init_db
from app.core.security import hash_password
from app.models.tables import User

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).parent / "static"

@asynccontextmanager
async def lifespan(_: FastAPI):
    """Create tables and seed the single administrator account."""
    init_db()
    settings.report_dir.mkdir(parents=True, exist_ok=True)
    session = SessionLocal()
    try:
        if session.query(User).filter(User.username == settings.seed_admin_user).first() is None:
            session.add(
                User(
                    username=settings.seed_admin_user,
                    password_hash=hash_password(settings.seed_admin_password),
                    role="admin",
                )
            )
            session.commit()
            logger.info("seeded administrator %s", settings.seed_admin_user)
        if settings.jwt_secret == "change-me-in-production":
            logger.warning(
                "ECDAT_JWT_SECRET is still the default value. Set it before any real deployment."
            )
    finally:
        session.close()
    yield


app = FastAPI(
    lifespan=lifespan,
    title="ECDAT",
    version=settings.version,
    description=(
        "Enterprise Cryptographic Discovery and Analysis Tool. One scan across "
        "code, TLS and certificates, producing a single risk scored inventory "
        "with post quantum readiness."
    ),
)

# The dashboard is served from the same origin, so this is only for development
# convenience when a separate frontend dev server is used.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

API_PREFIX = "/api/v1"
app.include_router(auth.router, prefix=API_PREFIX)
app.include_router(scans.router, prefix=API_PREFIX)
app.include_router(findings.router, prefix=API_PREFIX)
app.include_router(reports.router, prefix=API_PREFIX)
app.include_router(misc.router, prefix=API_PREFIX)


if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", include_in_schema=False)
def dashboard() -> FileResponse:
    """Serve the dashboard."""
    return FileResponse(STATIC_DIR / "index.html")
