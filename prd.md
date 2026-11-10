# Product Requirements Document
## Security Gateway (s-gates)

**Document Version:** 1.0  
**Status:** Draft  

> **Implementation note:** This PRD describes target requirements, not delivered capability. The current repository is a development prototype; its scanner logic is heuristic-only, and production startup is intentionally blocked until real scanners, antivirus/sandbox workflows, and external integrations are implemented and validated. See `README.md` for current scope.

---

# 1. Product Overview

## 1.1 Product Name

**Security Gates (S-Gates)**

S-Gates is an internal application security platform designed to assess applications, scripts, automation tools, and AI-generated code before they running in production environment

The initial version of S-Gates will intentionally avoid Git, CI/CD, and complex DevSecOps requirements.

Users or IT administrators will submit a complete source-code package in ZIP format. S-Gates will extract the package in a controlled environment, execute multiple security scanners, consolidate their findings, and produce a security assessment result.

### Core Security Engines

- **Trivy** for dependency, vulnerability, misconfiguration, secret, and package analysis.
- **Gitleaks** for credential and secret detection.
- **Semgrep** for static application security testing.
- **Sandbox Analysis** for selected high-risk applications.

---

# 2. Problem Statement

AI-assisted development significantly reduces the technical barrier to building applications.

Employees can now use tools such as:

- Microsoft Copilot
- ChatGPT
- Claude
- Gemini
- Cursor
- Replit
- Lovable
- Bolt
- Other AI coding tools

to generate complete applications and scripts.

This creates business opportunities but also increases the likelihood of unmanaged applications being developed outside normal IT processes.

Potential risks include:

- Shadow IT
- Shadow AI
- Vulnerable open-source packages
- Malicious packages
- Typosquatting packages
- Abandoned or unsupported packages
- Hardcoded passwords
- Exposed API keys and access tokens
- SQL injection
- Command injection
- Unsafe code execution
- Malware
- Unauthorized network communication
- Excessive permissions
- Unclear technical ownership
- Inadequate documentation
- Single-person dependencies
- Business continuity risk

Traditional application-development controls such as Git repositories, pull requests, CI/CD pipelines, and DevSecOps security gates may not yet be practical for all citizen-developed applications.

S-Gates therefore provides a lightweight security gateway between citizen development and business deployment.

---

# 3. Product Vision

> **Enable innovation without losing security visibility and governance.**

S-Gates should allow employees to continue developing useful applications while providing IT Security with a standardized mechanism to answer:

1. What application is being introduced?
2. Who owns it?
3. What source code does it contain?
4. What dependencies does it use?
5. Are known vulnerabilities present?
6. Are credentials or secrets embedded in the code?
7. Does the source code contain unsafe patterns?
8. Have malicious files been detected?
9. Does the application require additional sandbox testing?
10. Can the application proceed to a controlled pilot?

---

# 4. Product Goals

## 4.1 Primary Goals

S-Gates SHALL:

1. Provide centralized application security assessment.
2. Reduce Shadow IT and Shadow AI risk.
3. Require source-code submission before approval.
4. Detect known vulnerable dependencies.
5. Detect embedded credentials and secrets.
6. Detect common insecure coding patterns.
7. Integrate malware-validation results.
8. Produce standardized security reports.
9. Maintain an audit trail for security assessments.
10. Support users and IT teams without requiring Git knowledge.

---

# 5. Non-Goals

The MVP is NOT intended to:

- Replace penetration testing.
- Guarantee that an application is completely secure.
- Automatically determine whether all business logic is legitimate.
- Replace Trend Micro endpoint protection.
- Replace a vulnerability-management program.
- Replace enterprise DevSecOps platforms.
- Automatically execute arbitrary submitted applications.
- Automatically install dependencies from submitted applications.
- Automatically deploy applications into production.
- Automatically approve high-risk applications.

Future versions may integrate with Azure DevOps, GitHub, Freshservice, SharePoint workflows, CI/CD pipelines, and additional security platforms.

---

# 6. Target Users

## 6.1 Citizen Developer

Employees creating internal applications using traditional development or AI-assisted development.

Typical activities:

- Build an internal application.
- Package source code.
- Submit application for assessment.
- Review security findings.
- Remediate identified issues.
- Resubmit new versions.

---

## 6.2 IT Reviewer

IT personnel responsible for:

- Reviewing submissions.
- Reviewing scanner results.
- Validating security findings.
- Managing false positives.
- Requesting remediation.
- Running additional security checks.
- Recording approval decisions.

---

## 6.3 Security Reviewer

Responsible for higher-risk cases involving:

- Critical vulnerabilities
- Sensitive information
- External integrations
- Administrative privileges
- Security exceptions
- Obfuscated code
- Suspicious behavior
- Risk acceptance

---

## 6.4 Business Owner

Responsible for:

- Business justification.
- Application usage.
- Data purpose.
- User population.
- Acceptance of the application's business functionality.
- Continued business requirement.

---

# 7. Application Scope

Registration and assessment SHALL be required when an internally developed application meets one or more of the following conditions:

- Used by more than one employee.
- Accesses company information.
- Connects to SharePoint.
- Connects to OneDrive.
- Connects to SAP.
- Connects to a database.
- Consumes internal or external APIs.
- Processes personal or confidential information.
- Installs software.
- Requires administrative privileges.
- Creates background processes or services.
- Is substantially generated using AI-assisted development.

---

# 8. High-Level Architecture

```text
Employee / Citizen Developer
            |
            v
Application Registration
            |
            v
Upload Source Code ZIP
            |
            v
S-Gates Application Security Gateway
            |
    +-------+--------+-------+
    |                |       |
    v                v       v
  Trivy          Gitleaks  Semgrep
    |                |       |
    +-------+--------+-------+
            |
            v
    Assessment Engine
            |
            v
       Risk Decision
            |
       +----+----+
       |    |    |
       v    v    v
      PASS REVIEW REJECT
            |
            v
    Internal Antivirus/Security Scan
            |
            v
      Sandbox Gate
    if risk requires
            |
            v
      IT Final Review
            |
            v
       Pilot Approval
```

---

# 9. MVP User Journey

## 9.1 Submission

User opens S-Gates.

User selects:

**New Application Assessment**

User provides:

- Application name
- Department
- Business owner
- Technical owner
- Application description
- AI development tool used
- Application type
- Data classification
- External connections
- Expected number of users
- Administrator privileges required: Yes/No
- Source-code ZIP

User selects:

**Submit for Security Assessment**

---

# 10. Scan Workflow

After submission, S-Gates SHALL perform the following workflow:

```text
Submission
    |
    v
Validate ZIP
    |
    v
SHA-256 Hash
    |
    v
Safe Extraction
    |
    v
File Inventory
    |
    +---------------------+
    |          |          |
    v          v          v
 Trivy     Gitleaks    Semgrep
    |          |          |
    +----------+----------+
               |
               v
        Findings Parser
               |
               v
        Risk Evaluation
               |
               v
       Generate Report
```

S-Gates SHALL NOT execute submitted application code during static scanning.

---

# 11. ZIP Security Controls

Before extraction S-Gates SHALL validate:

- File extension.
- ZIP structure.
- Number of files.
- Expanded archive size.
- Path traversal attempts.
- Absolute paths.
- Nested suspicious locations.

Example protection:

```text
../../Windows/System32/example.exe
```

must cause the archive to be rejected.

Default configurable limits:

| Setting | MVP Default |
|---|---:|
| Maximum ZIP size | 500 MB |
| Maximum expanded size | 5 GB |
| Maximum file count | 50,000 |
| Maximum execution time | Configurable |

---

# 12. Security Scanner Requirements

## 12.1 Trivy

S-Gates SHALL run Trivy against the extracted application.

Required scanners:

```text
vuln
misconfig
secret
```

Trivy findings SHALL include where available:

- Vulnerability ID
- Package
- Installed version
- Fixed version
- Severity
- Target file
- Finding type

Severity classification:

- LOW
- MEDIUM
- HIGH
- CRITICAL

---

# 13. Gitleaks Requirements

S-Gates SHALL use Gitleaks to identify:

- API keys
- Passwords
- Tokens
- Cloud credentials
- Private keys
- Authentication secrets
- Other supported secret patterns

Secrets displayed in S-Gates SHALL be redacted.

Example:

```text
AWS Access Key
File: config.py
Line: 44
Value: ********************

Status: REJECT
```

The UI SHALL never display complete discovered secret values.

---

# 14. Semgrep Requirements

S-Gates SHALL perform static source-code analysis using Semgrep.

Initial rule coverage SHOULD include:

- SQL injection
- Command injection
- Unsafe subprocess execution
- Unsafe eval usage
- Insecure deserialization
- Authentication weaknesses
- Directory traversal
- Unsafe file operations
- Relevant OWASP patterns

Example:

```text
Finding:
Potential Command Injection

File:
processor.py

Severity:
HIGH

Scanner:
Semgrep
```

---

# 15. Antivirus/Security Scan Integration

## MVP

Antivirus/Security scanning MAY initially remain a manual gate.

Reviewer records:

```text
Antivirus/Security Scan

[ ] No Threat Detected
[ ] Threat Detected
[ ] Investigation Required
```

Evidence SHOULD be attached to the S-Gates assessment.

## Future Version

S-Gates SHOULD support automatic Trend Micro submission or scan integration when a supported and approved API or CLI mechanism has been validated.

---

# 16. Sandbox Analysis

Sandbox testing SHALL NOT automatically execute every application.

Sandbox SHALL be required when:

- EXE is present.
- MSI is present.
- Windows service is installed.
- Background agent is created.
- Scheduled tasks are created.
- Administrator privilege is required.
- Sensitive data is processed.
- External network communication occurs.
- Code is obfuscated.
- Static findings require behavioral investigation.

Possible sandbox technologies include:

- Windows Sandbox
- Hyper-V isolated VM
- Dedicated disposable test VM

---

# 17. Dependency Risk Assessment

S-Gates SHALL evaluate known dependency vulnerabilities through Trivy.

Examples:

```text
npm
pip
Maven
Go
NuGet
Container packages
```

Where dependency inventory is available, S-Gates SHOULD record:

```text
Package
Version
Ecosystem
Vulnerability
Severity
Fixed Version
```

---

# 18. Abandoned Package Review

Known-vulnerability scanning alone does not prove that a package remains adequately supported.

S-Gates SHOULD therefore support an additional reviewer status:

```text
SUPPORTED
MAINTENANCE REVIEW
ABANDONED
UNKNOWN
```

Reviewer criteria SHOULD include:

- Last package release.
- Maintainer status.
- Project activity.
- Availability of supported alternatives.
- Official publisher or registry identity.
- Known deprecation or end-of-life announcement.

Abandoned packages SHALL normally result in:

**REVIEW**

rather than automatic rejection unless security impact requires rejection.

---

# 19. Malicious Package Risk

S-Gates SHALL distinguish between:

**Known vulnerable package**

and

**Potentially malicious package**

A package without a published CVE cannot automatically be considered safe.

Additional controls MAY include:

- Package-name verification.
- Publisher verification.
- Typosquatting review.
- Install-script review.
- Trend Micro scanning.
- Sandbox execution.
- External network monitoring.

---

# 20. Risk Decision Engine

S-Gates SHALL support four technical statuses.

## PASS-WITH-MANUAL-CHECKS

Possible when:

- No Critical vulnerability.
- No exposed credential.
- No mandatory-review static finding.
- Static scanners complete successfully.

Manual controls remain required.

---

## REVIEW

Trigger examples:

- HIGH vulnerability.
- Semgrep security finding.
- Abandoned dependency.
- External integration.
- Sensitive information.
- Administrative privileges.
- High-risk application classification.
- Ambiguous scanner result.

---

## REJECT

Trigger examples:

- Confirmed active secret.
- CRITICAL vulnerability without remediation.
- Malware detection.
- Malicious dependency.
- Unauthorized data transmission.
- Missing source code.
- Deliberate unexplained code obfuscation.

---

## SCAN-ERROR

Used when:

- Scanner fails.
- ZIP cannot be processed.
- Security database unavailable.
- Report cannot be generated.
- Tool configuration is incomplete.

**SCAN-ERROR must never be interpreted as PASS.**

---

# 21. Example Assessment Dashboard

```text
--------------------------------------------------
 S-GATES SYSTEM
--------------------------------------------------

 Application: Sales Analytics Tool
 Version:     1.2
 Owner:       Sales
 Risk:        MEDIUM

 SECURITY ASSESSMENT

 Trivy
 --------------------------------
 Critical                  0
 High                      2
 Medium                    6
 Low                       4

 Gitleaks
 --------------------------------
 Secrets                   0

 Semgrep
 --------------------------------
 High                      1
 Medium                    3

 Antivirus/Security Scan
 --------------------------------
 No Threat Detected

 Sandbox
 --------------------------------
 Not Required

 --------------------------------
 SECURITY STATUS

              REVIEW
 --------------------------------

 [ View Findings ]

 [ Download Report ]

 [ Request Remediation ]

 [ Approve Pilot ]
```

---

# 22. Findings Dashboard

Reviewer SHALL be able to filter findings by:

- Scanner
- Severity
- Package
- Source file
- Finding type
- Remediation status

Example:

| Severity | Scanner | Finding | Status |
|---|---|---|---|
| Critical | Trivy | Vulnerable dependency | Open |
| High | Semgrep | Command injection | Open |
| Medium | Trivy | Outdated package | Accepted |
| High | Gitleaks | API token | Resolved |

---

# 23. Report Requirements

S-Gates SHALL generate:

### Executive Summary

```text
Application Name
Application Version
Business Owner
Technical Owner
Assessment Date
Risk Classification
Final Status
```

### Scanner Summary

```text
Trivy
Gitleaks
Semgrep
Antivirus/Security Scan
Sandbox
```

### Detailed Findings

```text
Finding ID
Scanner
Severity
Source
Description
Recommendation
Status
```

---

# 24. Evidence Artifacts

For every scan S-Gates SHALL maintain:

```text
Application/
|
+-- Submission/
|   +-- Source.zip
|
+-- Inventory/
|   +-- file-inventory.csv
|
+-- Reports/
|   +-- trivy-report.json
|   +-- trivy-report.txt
|   +-- gitleaks-report.json
|   +-- semgrep-report.json
|   +-- scan-summary.json
|   +-- scan-summary.html
|
+-- Evidence/
|   +-- antivirus-result
|   +-- sandbox-result
|
+-- Approval/
    +-- decision
```

---

# 25. Application Versioning

Each security assessment SHALL generate a unique assessment ID.

Recommended format:

```text
SG-YYYY-NNNNN
```

Example:

```text
SG-2026-00027
```

Application versions SHALL be separately assessed.

Example:

```text
Sales Dashboard
v1.0 -> S-GATES-2026-00027

Sales Dashboard
v1.1 -> S-GATES-2026-00044
```

Previous approval SHALL NOT automatically approve materially changed versions.

---

# 26. Application Inventory

S-Gates SHALL maintain a centralized inventory.

Minimum fields:

| Field | Description |
|---|---|
| S-Gates ID | Unique application registration |
| Application | Application name |
| Version | Submitted version |
| Department | Business department |
| Business Owner | Business accountability |
| Technical Owner | Technical accountability |
| AI Tool | AI development tool |
| Data Classification | Data sensitivity |
| Risk Level | Low / Medium / High |
| Security Status | Current S-Gates status |
| Scan Date | Last security scan |
| Production Status | Pilot / Production / Retired |
| Next Review | Planned reassessment |

---

# 27. Role-Based Access Control

## Citizen Developer

Can:

- Submit application.
- View own assessment.
- Download own report.
- Submit remediation.

Cannot:

- Approve application.
- Modify scanner result.
- Change risk classification.

---

## IT Reviewer

Can:

- View applications.
- Review findings.
- Classify false positives.
- Request remediation.
- Run security assessment.
- Recommend pilot approval.

---

## Security Reviewer

Can:

- Review high-risk findings.
- Review security exception.
- Record risk acceptance.
- Reject application.

---

## Administrator

Can:

- Configure scanner.
- Maintain rules.
- Update engines.
- Manage system configuration.

Administrator SHALL NOT be able to silently alter previously approved evidence.

---

# 28. Audit Requirements

S-Gates SHALL record:

- Submission date.
- Submitter.
- File hash.
- Scanner versions.
- Scan timestamp.
- Security findings.
- Status changes.
- Reviewer.
- Risk acceptance.
- Approval.
- Resubmission.
- Version changes.

Audit records SHOULD be immutable to normal users.

---

# 29. Security Requirements

S-Gates itself SHALL:

- Run using least privilege.
- Avoid Domain Administrator credentials.
- Avoid persistent production credentials.
- Sanitize file names.
- Prevent ZIP path traversal.
- Limit upload and expanded archive size.
- Validate uploaded file type.
- Record SHA-256 file hashes.
- Redact secrets from UI and normal reports.
- Protect the report repository.
- Delete temporary scan files according to retention policy.
- Maintain scanner versions.
- Maintain current vulnerability databases.

---

# 30. Scanner Database Failure

If vulnerability or rule databases cannot be updated, S-Gates SHALL display:

```text
Security Intelligence Status:
OUTDATED
```

Production approval SHOULD be blocked when:

```text
Trivy vulnerability database is unavailable
```

or required scanner configuration cannot be loaded.

This SHALL result in:

**SCAN-ERROR**

not PASS.

---

# 31. Availability and Recovery

MVP target:

**Business-hours service**

S-Gates is not initially considered a Tier-1 production service.

Recommended recovery targets:

```text
RTO: 1 business day
RPO: 24 hours
```

Application registration data and final security reports SHOULD reside in SharePoint or another centrally backed-up platform.

The scan station itself SHOULD be treated as rebuildable infrastructure.

---

# 32. Product Workflow

```text
REGISTER
    |
    v
SUBMIT CODE
    |
    v
STATIC SECURITY SCAN
    |
    v
FINDINGS
    |
    +----------+
    |          |
    v          v
 REMEDIATE   REVIEW
    |          |
    +----+-----+
         |
         v
 MALWARE CHECK
         |
         v
 SANDBOX IF REQUIRED
         |
         v
 IT APPROVAL
         |
         v
 LIMITED PILOT
         |
         v
 PRODUCTION
```

---

# 33. MVP Technology Architecture

Recommended initial technology:

| Component | Technology |
|---|---|
| Front End | Internal Web Application |
| API | Python FastAPI or .NET |
| Scanner Orchestrator | PowerShell |
| Dependency Scanner | Trivy |
| Secret Scanner | Gitleaks |
| SAST | Semgrep |
| Endpoint Security | Trend Micro |
| Runtime Test | Windows Sandbox / Hyper-V |
| Application Vault | SharePoint |
| Registration | S-Gates UI or Microsoft Forms |
| Reporting | HTML + JSON |
| Audit Repository | SharePoint / Database |

---

# 34. Recommended MVP Deployment

```text
S-Gates Web Application
        |
        v
   S-Gates Database
        |
        v
   Scan Queue
        |
        v
Dedicated Scanner VM
        |
   +----+----+----+
   |         |    |
 Trivy  Gitleaks Semgrep
   |         |    |
   +----+----+----+
        |
        v
Security Result Parser
        |
        v
S-Gates Assessment
        |
        v
SharePoint Evidence Vault
```

Submitted files SHOULD not be scanned directly from the web server.

Scanning SHOULD be performed by a dedicated worker or Scan Station.

---

# 35. Performance Requirements

Initial MVP targets:

| Requirement | Target |
|---|---:|
| Maximum ZIP | 500 MB |
| Maximum extracted size | 5 GB |
| Files per submission | 50,000 |
| Normal application scan | < 10 minutes target |
| Concurrent scans | 1 initially |
| Report generation | < 1 minute after scan |
| Submission retention | Policy-defined |

These values SHALL be configurable.

---

# 36. Notifications

S-Gates SHOULD notify relevant users when:

```text
Submission Received
Scan Started
Scan Completed
Remediation Required
Application Rejected
Pilot Approved
Assessment Expiring
```

Future integration:

**Microsoft Teams**

and/or:

**Email**

---

# 37. ITSM Tools Integration

Future S-Gates version SHOULD integrate with Freshservice or other ITSM Tools.

Example:

```text
S-Gates finding

Critical vulnerability
        |
        v
ITSM Vulnerability Ticket
        |
        v
Assigned Owner
        |
        v
Remediation SLA
        |
        v
S-Gates Rescan
```

This enables security findings to become operational remediation work instead of remaining static reports.

---

# 38. Success Metrics

S-Gates success SHALL be measured using:

| KPI | Target |
|---|---:|
| Registered citizen-developed apps | 100% of known scoped applications |
| Security-scanned applications | 100% before pilot |
| Critical findings unresolved at approval | 0 |
| Known exposed secrets at approval | 0 |
| Source code retained | 100% |
| Business owner defined | 100% |
| Technical owner defined | 100% |
| Scan evidence retained | 100% |

Additional metrics:

- Applications discovered outside S-Gates.
- Vulnerabilities detected before deployment.
- Secrets discovered.
- Applications rejected.
- Applications requiring remediation.
- Average assessment time.
- Vulnerability remediation time.

---

# 39. MVP Acceptance Criteria

The MVP is considered operational when:

- [ ] User can register an application.
- [ ] User can upload source ZIP.
- [ ] S-Gates validates ZIP security.
- [ ] S-Gates calculates SHA-256.
- [ ] S-Gates produces file inventory.
- [ ] Trivy executes successfully.
- [ ] Gitleaks executes successfully.
- [ ] Semgrep executes successfully.
- [ ] Findings are parsed.
- [ ] Secrets are redacted.
- [ ] Reports are generated.
- [ ] PASS / REVIEW / REJECT logic works.
- [ ] SCAN-ERROR cannot become PASS.
- [ ] Trend Micro evidence can be recorded.
- [ ] Sandbox requirement can be recorded.
- [ ] Reviewer can record final decision.
- [ ] Reports can be retained.
- [ ] Audit history is available.

---

# 40. Implementation Roadmap

## Phase 1: Security Engine

**Estimated duration: 2 to 4 weeks**

Build:

- Scanner VM.
- Trivy.
- Gitleaks.
- Semgrep.
- PowerShell orchestration.
- JSON reports.
- HTML summary.
- Manual Trend Micro workflow.

Objective:

> Prove the security engine works reliably.

---

## Phase 2: S-Gates MVP

**Estimated duration: 4 to 8 weeks**

Build:

- Web UI.
- Application registration.
- ZIP upload.
- Scan queue.
- Dashboard.
- Report viewer.
- Application inventory.
- Approval workflow.
- SharePoint evidence integration.

Objective:

> Make the security engine usable by ASEAN IT.

---

## Phase 3: Governance Automation

Introduce:

- Microsoft Teams notifications.
- Freshservice integration.
- Automated approval routing.
- Expiration and periodic review.
- Dependency inventory.
- Vulnerability reassessment.
- Security dashboard.

---

## Phase 4: DevSecOps Evolution

When organizational capability matures:

```text
Azure DevOps / GitHub
        |
        v
Commit / Pull Request
        |
        v
S-Gates API
        |
        v
Security Gate
        |
        v
PASS / FAIL
```

S-Gates should therefore be designed so that the scanning engine is API-capable even though Git integration is not required in the MVP.

---

# 41. Future Architecture Principle

The most important architectural requirement is separation between:

```text
S-Gates Portal
```

and

```text
S-Gates Security Engine
```

The portal manages:

- Users
- Registration
- Workflow
- Reports
- Approval
- Inventory

The security engine manages:

- Extraction
- Trivy
- Gitleaks
- Semgrep
- Finding normalization
- Risk calculation

This separation allows the same S-Gates Security Engine eventually to support:

```text
Web Upload
Microsoft Forms
SharePoint
Freshservice
Azure DevOps
GitHub
API
```

without rebuilding the underlying scanner.

---

# 42. Final Product Principle

S-Gates must never present a successful static scan as:

> **This application is safe.**

The correct wording is:

> **No blocking findings were identified by the configured automated security controls. Manual and risk-based validation requirements remain applicable.**

S-Gates is a **security decision-support and governance platform**, not a guarantee that an application is free from all security risk.

---

# 43. Product Tagline

**S-Gates Application Security Gateway**

> **Build Fast. Scan First. Deploy with Confidence.**
