from datetime import datetime, timezone
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    JSON,
)
from sqlalchemy.orm import relationship
from app.database import Base


def utcnow():
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    full_name = Column(String(255), nullable=False)
    department = Column(String(255), default="IT & Digital Innovation")
    role = Column(
        String(64), nullable=False, default="CITIZEN_DEVELOPER"
    )  # CITIZEN_DEVELOPER | IT_REVIEWER | SECURITY_REVIEWER | ADMIN
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)


class SystemSettings(Base):
    __tablename__ = "system_settings"

    id = Column(Integer, primary_key=True, index=True)
    max_zip_size_mb = Column(Integer, default=50)
    max_expanded_size_mb = Column(Integer, default=128)
    max_file_count = Column(Integer, default=5000)
    max_scan_seconds = Column(Integer, default=600)

    # PRD Section 30: Scanner Database Failure simulation & status
    security_intel_status = Column(
        String(64), default="UNAVAILABLE"
    )  # HEALTHY | OUTDATED | UNAVAILABLE
    trivy_db_available = Column(Boolean, default=False)
    trivy_version = Column(String(64), default="not-installed")
    gitleaks_version = Column(String(64), default="not-installed")
    semgrep_version = Column(String(64), default="not-installed")

    sharepoint_vault_url = Column(
        String(512),
        default="https://example.invalid/sharepoint-vault",
    )
    teams_webhook_url = Column(
        String(512),
        default="https://example.invalid/teams-webhook",
    )
    freshservice_domain = Column(String(255), default="example.invalid")
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class Application(Base):
    __tablename__ = "applications"

    id = Column(Integer, primary_key=True, index=True)
    sgates_app_id = Column(String(64), unique=True, index=True, nullable=False)
    name = Column(String(255), nullable=False, index=True)
    department = Column(String(255), nullable=False)
    business_owner = Column(String(255), nullable=False)
    technical_owner = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    ai_tool = Column(String(255), nullable=False, default="Cursor / Claude")
    app_type = Column(String(128), nullable=False, default="Web Application")
    data_classification = Column(
        String(128), nullable=False, default="Internal"
    )  # Public | Internal | Confidential | Restricted / Personal Data
    external_connections = Column(
        JSON, default=list
    )  # e.g. ["SharePoint", "SAP", "Database", "External API"]
    expected_users = Column(Integer, default=10)
    requires_admin_privileges = Column(Boolean, default=False)

    latest_version = Column(String(64), default="1.0")
    risk_level = Column(String(64), default="MEDIUM")  # LOW | MEDIUM | HIGH | CRITICAL
    security_status = Column(
        String(64), default="REVIEW"
    )  # PASS-WITH-MANUAL-CHECKS | REVIEW | REJECT | SCAN-ERROR
    production_status = Column(
        String(64), default="Pending Assessment"
    )  # Pending Assessment | Pilot | Production | Remediation Required | Rejected | Retired

    last_scan_date = Column(DateTime(timezone=True), default=utcnow)
    next_review_date = Column(String(64), default="2027-05-09")
    created_by_email = Column(String(255), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow)

    assessments = relationship(
        "Assessment",
        back_populates="application",
        cascade="all, delete-orphan",
        order_by="desc(Assessment.created_at)",
    )


class Assessment(Base):
    __tablename__ = "assessments"

    id = Column(Integer, primary_key=True, index=True)
    assessment_code = Column(
        String(64), unique=True, index=True, nullable=False
    )  # e.g. SG-2026-00027
    application_id = Column(
        Integer, ForeignKey("applications.id", ondelete="CASCADE"), nullable=False
    )
    version = Column(String(64), nullable=False)
    submitter_email = Column(String(255), nullable=False)
    submitter_name = Column(String(255), nullable=False)

    zip_filename = Column(String(255), nullable=False)
    zip_size_bytes = Column(Integer, default=0)
    expanded_size_bytes = Column(Integer, default=0)
    file_count = Column(Integer, default=0)
    sha256_hash = Column(String(128), nullable=False)

    zip_valid = Column(Boolean, default=True)
    zip_validation_errors = Column(JSON, default=list)
    file_inventory_preview = Column(JSON, default=list)

    # PRD Section 20: Technical Status
    technical_status = Column(
        String(64), nullable=False, default="REVIEW"
    )  # PASS-WITH-MANUAL-CHECKS | REVIEW | REJECT | SCAN-ERROR
    risk_level = Column(String(64), default="MEDIUM")  # LOW | MEDIUM | HIGH | CRITICAL
    status_reasons = Column(JSON, default=list)

    scanner_versions = Column(JSON, default=dict)
    trivy_summary = Column(JSON, default=dict)
    gitleaks_summary = Column(JSON, default=dict)
    semgrep_summary = Column(JSON, default=dict)

    # PRD Section 15: Antivirus / Trend Micro Security Scan
    av_status = Column(
        String(64), default="Pending"
    )  # Pending | No Threat Detected | Threat Detected | Investigation Required
    av_notes = Column(Text, default="")
    av_evidence_ref = Column(String(255), default="")
    av_reviewed_by = Column(String(255), default="")

    # PRD Section 16: Sandbox Analysis
    sandbox_required = Column(Boolean, default=False)
    sandbox_reasons = Column(JSON, default=list)
    sandbox_status = Column(
        String(64), default="Not Required"
    )  # Not Required | Required - Pending | Passed | Failed
    sandbox_technology = Column(
        String(128), default="Windows Sandbox"
    )  # Windows Sandbox | Hyper-V Isolated VM | Dedicated Disposable Test VM
    sandbox_notes = Column(Text, default="")
    sandbox_reviewed_by = Column(String(255), default="")

    # PRD Section 21, 27, 28: Final Approval / Decision
    final_decision = Column(
        String(64), default="PENDING_REVIEW"
    )  # PENDING_REVIEW | REMEDIATION_REQUESTED | PILOT_RECOMMENDED | PILOT_APPROVED | RISK_ACCEPTED | REJECTED
    decision_by = Column(String(255), default="")
    decision_role = Column(String(64), default="")
    decision_notes = Column(Text, default="")
    decision_at = Column(DateTime(timezone=True), nullable=True)

    # PRD Section 24: Evidence Vault & SharePoint
    evidence_vault_path = Column(String(512), default="")
    sharepoint_synced = Column(Boolean, default=False)
    sharepoint_url = Column(String(512), default="")

    created_at = Column(DateTime(timezone=True), default=utcnow)

    application = relationship("Application", back_populates="assessments")
    findings = relationship(
        "Finding", back_populates="assessment", cascade="all, delete-orphan"
    )
    dependencies = relationship(
        "DependencyItem", back_populates="assessment", cascade="all, delete-orphan"
    )


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    assessment_id = Column(
        Integer, ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False
    )
    finding_code = Column(String(64), nullable=False)  # e.g. FND-001
    scanner = Column(String(64), nullable=False)  # Trivy | Gitleaks | Semgrep
    finding_type = Column(
        String(64), nullable=False
    )  # vuln | misconfig | secret | sast
    severity = Column(String(32), nullable=False)  # CRITICAL | HIGH | MEDIUM | LOW
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    file_path = Column(String(512), nullable=False)
    line_number = Column(Integer, default=1)
    package_name = Column(String(255), default="")
    installed_version = Column(String(128), default="")
    fixed_version = Column(String(128), default="")
    vulnerability_id = Column(String(128), default="")
    redacted_value = Column(
        String(255), default="********************"
    )  # Never store raw secret!
    recommendation = Column(Text, default="")
    status = Column(
        String(64), default="Open"
    )  # Open | Accepted | False Positive | Resolved
    reviewer_comment = Column(Text, default="")
    itsm_ticket_id = Column(String(64), default="")
    created_at = Column(DateTime(timezone=True), default=utcnow)

    assessment = relationship("Assessment", back_populates="findings")


class DependencyItem(Base):
    __tablename__ = "dependency_items"

    id = Column(Integer, primary_key=True, index=True)
    assessment_id = Column(
        Integer, ForeignKey("assessments.id", ondelete="CASCADE"), nullable=False
    )
    package_name = Column(String(255), nullable=False)
    version = Column(String(128), nullable=False)
    ecosystem = Column(
        String(64), nullable=False
    )  # npm | pip | Maven | Go | NuGet | Container
    vulnerability_id = Column(String(128), default="None")
    severity = Column(String(32), default="NONE")  # CRITICAL | HIGH | MEDIUM | LOW | NONE
    fixed_version = Column(String(128), default="-")

    # PRD Section 18: Abandoned Package Review
    reviewer_status = Column(
        String(64), default="SUPPORTED"
    )  # SUPPORTED | MAINTENANCE REVIEW | ABANDONED | UNKNOWN
    last_release_date = Column(String(64), default="2026-04-12")
    maintainer_status = Column(String(128), default="Active Maintainers")
    publisher_identity = Column(String(128), default="Verified Registry Publisher")
    alternative_package = Column(String(255), default="-")

    # PRD Section 19: Malicious Package Risk
    malicious_risk = Column(
        String(64), default="Known Safe / Standard"
    )  # Known Safe / Standard | Known Vulnerable Package | Potentially Malicious Package | Typosquatting Suspect | Suspicious Install Script
    reviewer_notes = Column(Text, default="")

    assessment = relationship("Assessment", back_populates="dependencies")


class AuditRecord(Base):
    __tablename__ = "audit_records"

    id = Column(Integer, primary_key=True, index=True)
    assessment_code = Column(String(64), index=True, nullable=True)
    sgates_app_id = Column(String(64), index=True, nullable=True)
    actor_email = Column(String(255), nullable=False)
    actor_role = Column(String(64), nullable=False)
    event_type = Column(String(128), nullable=False)
    previous_state = Column(String(128), default="")
    new_state = Column(String(128), default="")
    sha256_file_hash = Column(String(128), default="")
    summary = Column(Text, nullable=False)
    metadata_json = Column(JSON, default=dict)
    immutable_signature = Column(String(128), nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow)


class NotificationEvent(Base):
    __tablename__ = "notification_events"

    id = Column(Integer, primary_key=True, index=True)
    event_type = Column(
        String(128), nullable=False
    )  # Submission Received | Scan Started | Scan Completed | Remediation Required | Application Rejected | Pilot Approved | Assessment Expiring
    assessment_code = Column(String(64), nullable=False)
    application_name = Column(String(255), nullable=False)
    recipient_role = Column(String(64), default="ALL")
    channel = Column(String(64), default="In-App + Teams + Email")
    message = Column(Text, nullable=False)
    is_read = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=utcnow)
