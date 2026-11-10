from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from app.api import admin, applications, assessments, auth, evidence
from app.config import settings, validate_runtime_settings
from app.database import Base, SessionLocal, engine
from app.engine.adapters.manager import default_scanner_manager
from app.engine.evidence_vault import MANDATORY_GOVERNANCE_DISCLAIMER
from app.engine.legacy_assessments import invalidate_legacy_assessments
from app.seed import seed_initial_data


@asynccontextmanager
async def lifespan(app: FastAPI):
    validate_runtime_settings()
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    try:
        seed_initial_data(
            db,
            include_demo_personas=settings.ENABLE_DEMO_ROLE_SWITCHER,
            include_demo_assessments=settings.SEED_DEMO_ASSESSMENTS,
        )
        invalidate_legacy_assessments(db)
    finally:
        db.close()
    yield


app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description=(
        "S-Gates development prototype — ZIP and GitHub intake with heuristic demo rules. "
        "This build does not execute external scanners and is not production-ready."
    ),
    lifespan=lifespan,
)

origins = [o.strip() for o in settings.ALLOWED_ORIGINS.split(",") if o.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_origin_regex=r"^https?://(localhost|127\.0\.0\.1|0\.0\.0\.0|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(:\d+)?$",
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix=settings.API_V1_STR)
app.include_router(applications.router, prefix=settings.API_V1_STR)
app.include_router(assessments.router, prefix=settings.API_V1_STR)
app.include_router(evidence.router, prefix=settings.API_V1_STR)
app.include_router(admin.router, prefix=settings.API_V1_STR)


@app.get("/health", tags=["System Health"])
def health_check():
    scanner_status = default_scanner_manager.get_scanner_status()
    all_ready = scanner_status["all_available"]
    return {
        "status": "healthy",
        "service": "s-gates-security-gateway",
        "version": settings.VERSION,
        "scanner_mode": scanner_status["scanner_mode"],
        "production_ready": all_ready,
        "security_intel_status": scanner_status["status"],
        "scanner_versions": {
            "trivy": scanner_status["trivy_version"],
            "gitleaks": scanner_status["gitleaks_version"],
            "semgrep": scanner_status["semgrep_version"],
        },
        "engines": (
            ["Aqua Security Trivy", "Gitleaks Credential Scanner", "Semgrep SAST", "ZIP-Security-Gate", "Risk-Decision-Engine"]
            if all_ready
            else ["S-Gates heuristic demo rules", "ZIP-Security-Gate", "Risk-Decision-Engine"]
        ),
        "governance_principle": MANDATORY_GOVERNANCE_DISCLAIMER,
    }


@app.get("/ready", tags=["System Health"])
def readiness_check():
    """Readiness check for the database dependency; scanner mode remains explicitly reported."""
    try:
        with engine.connect() as connection:
            connection.execute(text("SELECT 1"))
    except Exception:
        raise HTTPException(status_code=503, detail="Database is not ready.")
    scanner_status = default_scanner_manager.get_scanner_status()
    return {
        "status": "ready",
        "database": "connected",
        "scanner_mode": scanner_status["scanner_mode"],
        "production_ready": scanner_status["all_available"],
    }
