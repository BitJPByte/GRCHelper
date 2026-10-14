# Healthcare Continuous Compliance & Breach Triage Engine
**Automated Governance, Risk, and Compliance (GRC) & Technical Assurance for HIPAA, HITECH, 42 CFR Part 2, and NIST SP 800-53 Rev. 5**

## 1. Executive Summary
* **The Problem:** Healthcare compliance programs often struggle with static, spreadsheet-driven compliance that lags behind real-world infrastructure and workforce risk.
* **The Solution:** This repository implements a **Continuous Assurance & Breach Triage Engine** designed for behavioral health and Substance Use Disorder (SUD) treatment environments. Using the **NIST SP 800-66 Rev. 2** (*Implementing the HIPAA Security Rule*) crosswalk, this platform translates technical telemetry from **KnowBe4**, **Microsoft Intune (MDM)**, **Microsoft Entra ID (M365)**, **Third-Party Vendor BAA Inventories**, and **SIEM/EDR Alerts** directly into **NIST SP 800-53 Rev. 5** control assessments, a live **Information Security Risk Register (POA&M)**, and automated **HITECH / 42 CFR Part 2 Breach Risk Assessments**.

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
```

## 3. Architectural Scalability: Lab vs. Production Environment

| Component | Lab Implementation (Zero Cost / Dev) | Production: Less Complex / Budget-Friendly | Production: Complex / Enterprise Scale |
| :--- | :--- | :--- | :--- |
| **Data Ingestion** | Static local JSON file (`knowbe4_api_mock.json`) parsed via Python script. | Scheduled PowerShell scripts / Logic Apps querying APIs; logs sent to secure SharePoint / SQL. | Real-time event streaming via Microsoft Sentinel connectors, Azure Event Hubs, and OAuth webhooks. |
| **PII Protection** | Local HMAC-SHA256 with a hardcoded fallback salt in `security_utils.py`. | Local `.env` variables / basic secret storage; restricted HR mapping shares. | Managed secrets in **Azure Key Vault** with automated rotation; mapping tables secured via Purview & PIM. |
| **Endpoint / SUD Enforcement** | Custom Python conditional checks on mock device states. | Native **Microsoft Intune** compliance policies & Entra ID Conditional Access blocking. | Automated incident playbooks via **Microsoft Defender XDR** and **ServiceNow** GRC integration. |
| **Audit Reporting** | Python script generating CSV & stamping SHA-256 hash in Markdown. | Monthly audit reports saved to dedicated OneDrive/SharePoint with version history & retention labels. | Immutable Storage (WORM) on Azure Blob Storage ensuring tamper-evidence under HIPAA 164.312(c)(1). |