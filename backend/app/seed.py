from datetime import datetime, timezone
from sqlalchemy.orm import Session
from app.engine.orchestrator import (
    execute_full_assessment,
    get_or_create_system_settings,
)
from app.config import settings
from app.engine.sample_generator import generate_sample_zip
from app.models import Assessment, User
from app.security import get_password_hash, record_audit_event


def seed_initial_data(
    db: Session,
    include_demo_personas: bool = False,
    include_demo_assessments: bool = False,
) -> None:
    get_or_create_system_settings(db)

    if settings.ADMIN_EMAIL and settings.ADMIN_PASSWORD:
        admin = db.query(User).filter(User.email == settings.ADMIN_EMAIL).first()
        if not admin:
            admin = User(
                email=settings.ADMIN_EMAIL,
                full_name="S-Gates Administrator",
                department="Platform & Security Engineering",
                role="ADMIN",
                hashed_password=get_password_hash(settings.ADMIN_PASSWORD),
                is_active=True,
            )
            db.add(admin)
        else:
            admin.role = "ADMIN"
            admin.hashed_password = get_password_hash(settings.ADMIN_PASSWORD)
            admin.is_active = True

    if include_demo_personas:
        default_pw = get_password_hash("SGates2026!")
        personas = [
            ("citizen.dev@sgates.local", "Alex Rivera (Citizen Developer)", "Sales & Commercial Operations", "CITIZEN_DEVELOPER"),
            ("it.reviewer@sgates.local", "Priya Nair (ASEAN IT Reviewer)", "Regional IT Governance", "IT_REVIEWER"),
            ("sec.reviewer@sgates.local", "Marcus Vance (Lead Security Reviewer)", "Information Security & Risk", "SECURITY_REVIEWER"),
            ("admin@sgates.local", "Local Demo Administrator", "Platform & Security Engineering", "ADMIN"),
        ]
        for email, full_name, department, role in personas:
            existing_user = db.query(User).filter(User.email == email).first()
            if not existing_user:
                db.add(User(email=email, full_name=full_name, department=department, role=role, hashed_password=default_pw, is_active=True))
    db.commit()

    if not include_demo_assessments:
        return

    # Check if assessments are already seeded
    if db.query(Assessment).count() > 0:
        return

    # 2. Seed SG-2026-00027 (Sales Analytics Tool v1.0 — Earlier version in lineage per PRD Section 25)
    _, zip_clean = generate_sample_zip("clean")
    execute_full_assessment(
        db=db,
        zip_bytes=zip_clean,
        zip_filename="sales-analytics-tool-v1.0.zip",
        app_name="Sales Analytics Tool",
        version="1.0",
        department="Sales",
        business_owner="VP Regional Sales (ASEAN)",
        technical_owner="Alex Rivera (Citizen Developer)",
        description="Initial prototype of regional sales forecasting & commission tracker built with Claude & Lovable.",
        ai_tool="Claude + Lovable",
        app_type="Internal Web Application",
        data_classification="Internal",
        external_connections=["SharePoint"],
        expected_users=35,
        requires_admin_privileges=False,
        submitter_email="citizen.dev@sgates.local",
        submitter_name="Alex Rivera (Citizen Developer)",
        submitter_role="CITIZEN_DEVELOPER",
        custom_assessment_code="SG-2026-00027",
    )
    # Demo data must not imply a real security approval.

    # 3. Seed SG-2026-00044 (Sales Analytics Tool v1.2 — Matches PRD Section 21 & 25 Dashboard Example -> REVIEW)
    _, zip_review = generate_sample_zip("review")
    execute_full_assessment(
        db=db,
        zip_bytes=zip_review,
        zip_filename="sales-analytics-tool-v1.2.zip",
        app_name="Sales Analytics Tool",
        version="1.2",
        department="Sales",
        business_owner="VP Regional Sales (ASEAN)",
        technical_owner="Alex Rivera (Citizen Developer)",
        description="v1.2 adds automated CSV export processor and SharePoint/BI ingestion endpoints.",
        ai_tool="Claude + Lovable",
        app_type="Internal Web Application",
        data_classification="Confidential",
        external_connections=["SharePoint", "External API"],
        expected_users=60,
        requires_admin_privileges=False,
        submitter_email="citizen.dev@sgates.local",
        submitter_name="Alex Rivera (Citizen Developer)",
        submitter_role="CITIZEN_DEVELOPER",
        custom_assessment_code="SG-2026-00044",
    )

    # 4. Seed SG-2026-00045 (Manufacturing KPI Calculator v1.0 -> PASS-WITH-MANUAL-CHECKS)
    execute_full_assessment(
        db=db,
        zip_bytes=zip_clean,
        zip_filename="clean-kpi-calculator-v1.0.zip",
        app_name="Manufacturing KPI Calculator",
        version="1.0",
        department="Manufacturing & Supply Chain",
        business_owner="Director of Plant Operations",
        technical_owner="Kenji Takahashi (Process Engineer)",
        description="Standalone plant OEE (Overall Equipment Effectiveness) and cycle-time calculator generated with Cursor.",
        ai_tool="Cursor",
        app_type="Web Application / Utility",
        data_classification="Internal",
        external_connections=["OneDrive"],
        expected_users=20,
        requires_admin_privileges=False,
        submitter_email="citizen.dev@sgates.local",
        submitter_name="Alex Rivera (Citizen Developer)",
        submitter_role="CITIZEN_DEVELOPER",
        custom_assessment_code="SG-2026-00045",
    )
    # Demo assessment metadata is not evidence of a real approval or SharePoint sync.
    db.commit()

    # 5. Seed SG-2026-00046 (Shadow AI SAP Inventory Sync Agent v0.9 -> REJECT)
    _, zip_reject = generate_sample_zip("reject")
    a_reject = execute_full_assessment(
        db=db,
        zip_bytes=zip_reject,
        zip_filename="shadow-ai-sap-sync-v0.9.zip",
        app_name="Shadow AI SAP Inventory Sync Agent",
        version="0.9",
        department="Logistics & Warehousing",
        business_owner="Head of Warehouse Logistics",
        technical_owner="External Contractor / Bolt AI",
        description="Background Windows service that syncs SAP vendor master tables with external AI pricing webhook.",
        ai_tool="Bolt + ChatGPT",
        app_type="Background Service / Automation Script",
        data_classification="Restricted / Personal Data",
        external_connections=["SAP", "Database", "External API"],
        expected_users=120,
        requires_admin_privileges=True,
        submitter_email="citizen.dev@sgates.local",
        submitter_name="Alex Rivera (Citizen Developer)",
        submitter_role="CITIZEN_DEVELOPER",
        custom_assessment_code="SG-2026-00046",
    )
    a_reject.decision_by = "Marcus Vance (Lead Security Reviewer)"
    a_reject.decision_role = "SECURITY_REVIEWER"
    a_reject.decision_notes = (
        "Automatic REJECT confirmed: Embedded AWS Access Key in config.py:44, typosquatted 'reqeusts' package, "
        "Critical PyYAML/PyCrypto CVEs, obfuscated exec payload, and unsigned .exe installer."
    )
    a_reject.decision_at = datetime.now(timezone.utc)
    db.commit()

    # 6. Seed SG-2026-00047 (HR Onboarding Document Parser v1.0 -> SCAN-ERROR per PRD Section 20 & 30)
    execute_full_assessment(
        db=db,
        zip_bytes=zip_clean,
        zip_filename="hr-onboarding-parser-v1.0.zip",
        app_name="HR Onboarding Document Parser",
        version="1.0",
        department="Human Resources",
        business_owner="Regional HR Director",
        technical_owner="Siti Rahma (HR Ops Analyst)",
        description="AI-assisted resume and onboarding form extractor built with Microsoft Copilot.",
        ai_tool="Microsoft Copilot",
        app_type="Automation Script",
        data_classification="Restricted / Personal Data",
        external_connections=["SharePoint", "OneDrive"],
        expected_users=15,
        requires_admin_privileges=False,
        submitter_email="citizen.dev@sgates.local",
        submitter_name="Alex Rivera (Citizen Developer)",
        submitter_role="CITIZEN_DEVELOPER",
        custom_assessment_code="SG-2026-00047",
        force_scan_error_reason="Trivy vulnerability database was unreachable during scheduled offline window. SCAN-ERROR enforced (cannot be interpreted as PASS).",
    )

    record_audit_event(
        db=db,
        actor_email="admin@sgates.local",
        actor_role="ADMIN",
        event_type="SYSTEM_INITIALIZED",
        summary="S-Gates Security Engine & Governance Portal initialized with baseline policies and sample assessments.",
    )
    db.commit()
