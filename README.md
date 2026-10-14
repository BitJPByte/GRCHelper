# Healthcare Continuous Compliance & Breach Triage Engine
**Automated Governance, Risk, and Compliance (GRC) & Technical Assurance for HIPAA, HITECH, 42 CFR Part 2, and NIST SP 800-53 Rev. 5**

## 1. Executive Summary
The Problem: Healthcare compliance programs often rely on manual, point-in-time spreadsheets that quickly drift from real-world infrastructure and workforce risks.

The Solution: An automated GRC pipeline that ingests live telemetry from identity and endpoint tools (KnowBe4, Microsoft Intune) and continuously evaluates it against HIPAA Security Rule (45 CFR § 164.308–312), HITECH, 42 CFR Part 2 (Substance Use Disorder records), and NIST SP 800-53 Rev. 5 controls.

Audit-Ready Deliverables: Automatically outputs an actionable Information Security Risk Register (POA&M), a CISO executive dashboard complete with severity and category charts, and a cryptographic SHA-256 integrity hash to guarantee audit tamper-evidence under HIPAA § 164.312(c)(1).

---

## 2. Architecture & Continuous Monitoring Workflow

```text
+-------------------------------------------------------------------------+
|                   EXTERNAL TELEMETRY & DATA SOURCES                     |
+-------------------------------------------------------------------------+
  |                             |                           |
  v                             v                           v
[KnowBe4 Reporting API]   [MS Graph API: Intune/Entra]   [TPRM & BAA CSV]
- /v1/users (Phish %)     - BitLocker Encryption         - PHI/Part 2 Access
- /v1/training (Overdue)  - Conditional Access / MFA     - Signed BAA & SLA
- Repeat Clickers (90d)   - CrowdStrike Sensor Health    - SOC 2 / HITRUST
  |                             |                           |
  +-----------------------------+---------------------------+
                                |
                                v
+-------------------------------------------------------------------------+
|               HARDENED SECURITY LAYER (security_utils.py)               |
|  * HMAC-SHA256 PII Pseudonymization (HIPAA Minimum Necessary 164.502(b))|
|  * CSV Formula Injection (DDE) Neutralization (CWE-1236 / NIST SI-10)   |
|  * SSRF Host Allowlisting, TLS 1.3 Enforcement & Path Traversal Jailing |
+-------------------------------------------------------------------------+
                                |
                                v
+-------------------------------------------------------------------------+
|            CORE COMPLIANCE & TRIAGE ENGINE (engine/)                    |
|  1. continuous_compliance_auditor.py  (Workforce, MDM, & Vendor BAA)    |
|  2. hitech_breach_triage.py           (SIEM Alert -> 4-Factor LoProCo)  |
+-------------------------------------------------------------------------+
                                |
                                v
+-------------------------------------------------------------------------+
|                  AUDIT-READY ARTIFACTS (output/)                        |
|  * live_hipaa_risk_register.csv (+ SHA-256 Tamper-Evident Manifest)     |
|  * ciso_executive_dashboard.md  (Program Maturity & CAP Tracking)       |
+-------------------------------------------------------------------------+
