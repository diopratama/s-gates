import os
from typing import Optional
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    PROJECT_NAME: str = "S-Gates Application Security Gateway"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api/v1"
    APP_ENV: str = os.getenv("APP_ENV", "development")
    ENABLE_DEMO_ROLE_SWITCHER: bool = False
    SEED_DEMO_ASSESSMENTS: bool = False

    DATABASE_URL: str = os.getenv(
        "DATABASE_URL", "sqlite:///./s_gates_local.db"
    )
    SECRET_KEY: str = os.getenv("SECRET_KEY", "")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60

    ADMIN_EMAIL: Optional[str] = os.getenv("ADMIN_EMAIL")
    ADMIN_PASSWORD: Optional[str] = os.getenv("ADMIN_PASSWORD")

    # ZIP Security Controls (PRD Section 11 & 35)
    MAX_ZIP_SIZE_MB: int = min(int(os.getenv("MAX_ZIP_SIZE_MB", "50")), 50)
    MAX_EXPANDED_SIZE_MB: int = min(int(os.getenv("MAX_EXPANDED_SIZE_MB", "128")), 128)
    MAX_FILE_COUNT: int = min(int(os.getenv("MAX_FILE_COUNT", "5000")), 5000)
    MAX_SCAN_SECONDS: int = min(int(os.getenv("MAX_SCAN_SECONDS", "120")), 120)

    # Real Security Scanners Configuration (Trivy, Gitleaks, Semgrep, OSV-Scanner, GuardDog)
    SCANNER_EXECUTION_MODE: str = os.getenv("SCANNER_EXECUTION_MODE", "auto")  # auto | external_only | heuristic_demo
    TRIVY_BINARY_PATH: str = os.getenv("TRIVY_BINARY_PATH", "trivy")
    GITLEAKS_BINARY_PATH: str = os.getenv("GITLEAKS_BINARY_PATH", "gitleaks")
    SEMGREP_BINARY_PATH: str = os.getenv("SEMGREP_BINARY_PATH", "semgrep")
    OSV_SCANNER_BINARY_PATH: str = os.getenv("OSV_SCANNER_BINARY_PATH", "osv-scanner")
    GUARDDOG_BINARY_PATH: str = os.getenv("GUARDDOG_BINARY_PATH", "guarddog")
    GUARDDOG_MAX_PACKAGES: int = int(os.getenv("GUARDDOG_MAX_PACKAGES", "20"))
    SUPPLY_CHAIN_CACHE_TTL_SECONDS: int = int(os.getenv("SUPPLY_CHAIN_CACHE_TTL_SECONDS", "21600"))
    REGISTRY_HTTP_TIMEOUT_SECONDS: int = int(os.getenv("REGISTRY_HTTP_TIMEOUT_SECONDS", "8"))
    SCANNER_TIMEOUT_SECONDS: int = min(int(os.getenv("SCANNER_TIMEOUT_SECONDS", "60")), 120)

    # Evidence Vault & Integrations
    EVIDENCE_VAULT_DIR: str = os.getenv(
        "EVIDENCE_VAULT_DIR",
        os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "evidence_vault"),
    )
    SHAREPOINT_VAULT_URL: str = os.getenv(
        "SHAREPOINT_VAULT_URL",
        "https://example.invalid/sharepoint-vault",
    )
    TEAMS_WEBHOOK_URL: str = os.getenv(
        "TEAMS_WEBHOOK_URL",
        "https://example.invalid/teams-webhook",
    )
    FRESHSERVICE_DOMAIN: str = os.getenv(
        "FRESHSERVICE_DOMAIN", "example.invalid"
    )

    ALLOWED_ORIGINS: str = os.getenv(
        "ALLOWED_ORIGINS",
        "http://localhost:3003,http://127.0.0.1:3003,http://localhost:3000,http://127.0.0.1:3000",
    )

settings = Settings()


def validate_runtime_settings() -> None:
    """Fail closed when production auth is configured with demo credentials."""
    app_env = settings.APP_ENV.lower()
    if app_env == "test":
        return
    if app_env == "development":
        if len(settings.SECRET_KEY) < 32:
            raise RuntimeError("Development requires a SECRET_KEY of at least 32 characters.")
        if not settings.ADMIN_EMAIL or not settings.ADMIN_PASSWORD:
            raise RuntimeError("Set ADMIN_EMAIL and ADMIN_PASSWORD in .env before starting the app.")
        return

    if (
        len(settings.SECRET_KEY) < 32
        or settings.SECRET_KEY in {
            "s-gates-enterprise-security-gateway-secret-key-2026",
            "local-development-only-change-before-deployment",
        }
    ):
        raise RuntimeError("Production requires a unique SECRET_KEY of at least 32 characters.")
    if not settings.ADMIN_EMAIL or not settings.ADMIN_PASSWORD:
        raise RuntimeError("Production requires ADMIN_EMAIL and ADMIN_PASSWORD for the bootstrap administrator.")
    if settings.ADMIN_PASSWORD == "SGates2026!" or len(settings.ADMIN_PASSWORD) < 16:
        raise RuntimeError("Production ADMIN_PASSWORD must be unique and at least 16 characters.")
    if settings.ENABLE_DEMO_ROLE_SWITCHER or settings.SEED_DEMO_ASSESSMENTS:
        raise RuntimeError("Demo role switching and demo assessment seeding are disabled in production.")
    raise RuntimeError(
        "Production startup is disabled: this build does not contain validated external scanner adapters."
    )
