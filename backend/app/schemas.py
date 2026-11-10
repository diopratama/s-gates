from datetime import datetime
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, ConfigDict, Field, SecretStr


class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    email: str  # Demo personas use non-deliverable addresses under .local.
    full_name: str
    department: str
    role: str
    is_active: bool

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserOut


class LoginRequest(BaseModel):
    email: str
    password: str


class RoleSwitchRequest(BaseModel):
    role: str  # CITIZEN_DEVELOPER | IT_REVIEWER | SECURITY_REVIEWER | ADMIN


class FindingUpdateRequest(BaseModel):
    status: Literal["Open", "Accepted", "False Positive", "Resolved"]
    reviewer_comment: Optional[str] = ""


class DependencyUpdateRequest(BaseModel):
    reviewer_status: Literal["SUPPORTED", "MAINTENANCE REVIEW", "ABANDONED", "UNKNOWN"]
    malicious_risk: Optional[str] = None
    reviewer_notes: Optional[str] = ""


class ManualGateUpdateRequest(BaseModel):
    av_status: Optional[Literal["Pending", "No Threat Detected", "Threat Detected", "Investigation Required"]] = None
    av_notes: Optional[str] = None
    av_evidence_ref: Optional[str] = None
    sandbox_status: Optional[Literal["Not Required", "Required - Pending", "Passed", "Failed"]] = None
    sandbox_technology: Optional[str] = None
    sandbox_notes: Optional[str] = None


class ApprovalDecisionRequest(BaseModel):
    decision: Literal["REMEDIATION_REQUESTED", "PILOT_RECOMMENDED", "PILOT_APPROVED", "RISK_ACCEPTED", "REJECTED"]
    notes: str = Field(..., min_length=3)
    production_status: Optional[Literal["Pilot", "Production", "Remediation Required", "Rejected", "Retired", "Pilot (Risk Accepted)"]] = None


class SystemSettingsUpdateRequest(BaseModel):
    max_zip_size_mb: Optional[int] = Field(default=None, ge=1, le=50)
    max_expanded_size_mb: Optional[int] = Field(default=None, ge=1, le=128)
    max_file_count: Optional[int] = Field(default=None, ge=1, le=5000)
    max_scan_seconds: Optional[int] = Field(default=None, ge=1, le=120)
    security_intel_status: Optional[Literal["HEALTHY", "OUTDATED", "UNAVAILABLE"]] = None
    trivy_db_available: Optional[bool] = None
    sharepoint_vault_url: Optional[str] = None
    teams_webhook_url: Optional[str] = None
    freshservice_domain: Optional[str] = None


class SampleSubmissionRequest(BaseModel):
    preset: str  # clean | review | reject | traversal
    application_name: Optional[str] = None
    version: Optional[str] = "1.0"
    department: Optional[str] = "Operations & Finance"
    business_owner: Optional[str] = "Sarah Chen (VP Operations)"
    technical_owner: Optional[str] = "Alex Rivera (Citizen Developer)"
    ai_tool: Optional[str] = "Cursor + Claude 3.7 Sonnet"
    app_type: Optional[str] = "Internal Web Application"
    data_classification: Optional[str] = "Internal"
    external_connections: Optional[List[str]] = None
    expected_users: Optional[int] = 25
    requires_admin_privileges: Optional[bool] = False
    description: Optional[str] = None


class GitHubSubmissionRequest(BaseModel):
    repository_url: str = Field(..., min_length=1, max_length=512)
    branch: Optional[str] = Field(default=None, max_length=255)
    github_token: Optional[SecretStr] = Field(default=None, max_length=500, repr=False)
    application_name: str = Field(..., min_length=1, max_length=255)
    version: str = Field(default="1.0", max_length=64)
    department: str = Field(..., min_length=1, max_length=255)
    business_owner: str = Field(..., min_length=1, max_length=255)
    technical_owner: str = Field(..., min_length=1, max_length=255)
    description: str = Field(default="", max_length=5000)
    ai_tool: str = Field(default="Cursor", max_length=255)
    app_type: str = Field(default="Internal Web Application", max_length=128)
    data_classification: str = Field(default="Internal", max_length=128)
    external_connections: List[str] = Field(default_factory=list)
    expected_users: int = Field(default=10, ge=1)
    requires_admin_privileges: bool = False
