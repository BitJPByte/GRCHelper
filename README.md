# Healthcare Continuous Compliance & Breach Triage Engine
**Automated Governance, Risk, and Compliance (GRC) & Technical Assurance for HIPAA, HITECH, 42 CFR Part 2, and NIST SP 800-53 Rev. 5**

## 1. Executive Summary
* **The Problem:** Healthcare compliance programs often struggle with static, spreadsheet-driven compliance that lags behind real-world infrastructure and workforce risk.
* **The Solution:** This repository implements a **Continuous Assurance & Breach Triage Engine** designed for behavioral health and Substance Use Disorder (SUD) treatment environments. Using the **NIST SP 800-66 Rev. 2** (*Implementing the HIPAA Security Rule*) crosswalk, this platform translates technical telemetry from **KnowBe4**, **Microsoft Intune (MDM)**, **Microsoft Entra ID (M365)**, **Third-Party Vendor BAA Inventories**, and **SIEM/EDR Alerts** directly into **NIST SP 800-53 Rev. 5** control assessments, a live **Information Security Risk Register (POA&M)**, and automated **HITECH / 42 CFR Part 2 Breach Risk Assessments**.


| Feature | HIPAA Security Rule (45 CFR 164)	| NIST SP 800-66 Rev. 2	| NIST SP 800-53 Rev. 5 | 
| :--- | :--- | :--- | :--- |
| **What it is** | Federal Healthcare Law (HHS OCR) | Healthcare Implementation & Mapping Guide	| Master Catalog of Technical Security Controls |
| **Focus** | Protecting ePHI (Electronic Protected Health Info) | Translating HIPAA law into actionable security activities | Securing any IT system (Cloud, On-Prem, Hybrid) |
| **Structure** | 3 Safeguards: Administrative (164.308), Physical (164.310), Technical (164.312) | Key Activities, Sample Questions, & Crosswalk Tables | 20 Control Families (AC, AT, AU, IR, MP, RA, SC, SI, SR, etc.) |
| **Purpose** | Legal requirement; fines for breaches or missing BAAs | Tells you how to run a HIPAA Security Risk Assessment (SRA) | Gives your IT, M365, and SIEM teams concrete controls to configure|



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


## 4. Glossary of Terms & Regulatory Acronyms

To ensure cross-functional alignment between engineering, legal, clinical operations, and executive leadership, this section defines key compliance frameworks, governance artifacts, and regulatory acronyms used throughout this engine:

| Acronym / Term | Full Name / Regulatory Scope | Plain-Language Definition & Operational Impact |
| :--- | :--- | :--- |
| **BAA** | Business Associate Agreement (HIPAA 45 CFR § 164.502(e) / § 164.504(e)) | A legally binding contract required between a covered healthcare entity and an external vendor/subcontractor handling ePHI. It legally binds the vendor to implement administrative, physical, and technical safeguards. |
| **POA&M** | Plan of Action and Milestones (NIST SP 800-53 CA-5) | A structured management document that identifies security tasks, required resources, remediation milestones, and scheduled completion dates for known vulnerabilities or compliance gaps. |
| **CAP** | Corrective Action Plan (HHS / OCR Enforcement) | A formal remediation strategy mandated by executive leadership or regulatory oversight bodies (like the HHS Office for Civil Rights) outlining the precise root-cause fixes for policy or audit failures. |
| **SRA** | Security Risk Assessment (HIPAA 45 CFR § 164.308(a)(1)(ii)(A)) | The foundational HIPAA requirement to conduct an accurate and thorough assessment of the potential risks and vulnerabilities to the confidentiality, integrity, and availability of electronic PHI held by an organization. |
| **ePHI** | Electronic Protected Health Information | Individually identifiable health information transmitted or maintained in electronic media (e.g., medical records, lab results, billing history). |
| **42 CFR Part 2** | Confidentiality of Substance Use Disorder Patient Records | Strict federal regulations protecting medical and diagnostic records related to substance use disorder (SUD) diagnosis, treatment, and referral. Unauthorized disclosure carries criminal penalties and strict liability beyond standard HIPAA rules. |
| **HITECH Act** | Health Information Technology for Economic and Clinical Health Act | Legislation establishing strict breach notification requirements (45 CFR §§ 164.400–414), creating mandatory 60-day breach reporting windows to HHS/OCR, and establishing the **Breach Safe Harbor** for NIST-approved encrypted data. |
| **LoProCo** | Low Probability of Compromise (45 CFR § 164.402) | The four-factor legal breach triage test used by privacy officers and incident responders to determine whether an unauthorized acquisition, access, use, or disclosure of ePHI requires mandatory government/patient notification. |
| **TPRM** | Third-Party Risk Management (NIST SP 800-53 SA-9) | The continuous process of vetting, assessing, monitoring, and mitigating security risks introduced by external software vendors, service providers, and contractors. |
| **DDE** | Dynamic Data Exchange (CWE-1236 / CSV Formula Injection) | An attack vector where malicious formulas (starting with `=`, `+`, `-`, or `@`) are placed in plain-text records so that opening an exported CSV in spreadsheet software (like Microsoft Excel) triggers automatic command execution. |
| **WORM** | Write Once, Read Many (HIPAA 45 CFR § 164.312(c)(1)) | Immutable data storage architecture preventing records or audit logs from being modified, overwritten, or deleted during their retention lifecycle, ensuring non-repudiation for federal auditors. |