# Healthcare Continuous Compliance & Breach Triage Lab

[![Continuous HIPAA & NIST Compliance Pipeline](https://github.com/BitJPByte/GRCHelper/actions/workflows/compliance_audit.yml/badge.svg)](https://github.com/BitJPByte/GRCHelper/actions/workflows/compliance_audit.yml)

**Automated GRC Auditing & Breach Triage for HIPAA, HITECH, 42 CFR Part 2, NIST SP 800-53 Rev. 5, and NIST CSF 2.0**

---

## Table of Contents
* [1. Overview](#1-overview)
* [2. Architecture & Data Flow](#2-architecture--data-flow)
* [3. Getting Started (How-To)](#3-getting-started-how-to)
* [4. Sample Audit Outputs](#4-sample-audit-outputs)
* [5. Lab vs. Production Roadmap](#5-lab-vs-production-roadmap)
* [6. Regulatory & Technical Glossary](#6-regulatory--technical-glossary)

<br>

---

## 1. Overview
* **The Challenge:** In many organizations, compliance tracking still lives in static spreadsheets. The moment an audit wraps up, those spreadsheets start drifting from what is actually happening across endpoints, user identities, and third-party vendors.
* **What This Project Does:** I built this Python lab to automate continuous compliance checks for a behavioral health and Substance Use Disorder (SUD) environment. Using **NIST SP 800-66 Rev. 2** (*Implementing the HIPAA Security Rule*) as the bridge between legal requirements and technical controls, the script takes mock telemetry from **KnowBe4**, **Microsoft Intune**, **Microsoft Entra ID**, and a **Third-Party Vendor (TPRM) BAA inventory**, and maps every gap directly to **HIPAA**, **42 CFR Part 2**, **HITECH**, **NIST SP 800-53 Rev. 5**, and **NIST CSF 2.0**.
* **What It Produces:** Every run generates a clean **CSV Risk Register (POA&M)** for GRC/ticketing import, **visual compliance charts**, a **CISO Executive Summary**, and a **HITECH 4-Factor Breach Triage Report**. Each report is stamped with a **SHA-256 file hash** to support audit log integrity under **HIPAA 45 CFR § 164.312(c)(1)**.

<br>

---

## 2. Architecture & Data Flow

```text
+-----------------------------------------------------------------------------------+
|               EXTERNAL TELEMETRY & REGULATORY REFERENCE SOURCES                   |
+-----------------------------------------------------------------------------------+
   |                        |                         |                      |
   v                        v                         v                      v
[KnowBe4 API]       [MS Graph: Intune/Entra]   [TPRM & BAA JSON]    [NIST CPRT JSON Export]
- Phish Prone %     - BitLocker Encryption     - Active PHI Access  - SP 800-66 Rev. 2
- Overdue Training  - Conditional Access MFA   - Signed BAA Status  - SP 800-53 Rev. 5
- Repeat Clickers   - Endpoint Sensor Health   - SOC 2 / HITRUST    - NIST CSF 2.0
   |                        |                         |                      |
   |                        |                         |                      v
   |                        |                         |          [build_crosswalk_from_nist.py]
   |                        |                         |                      |
   |                        |                         |                      v
   |                        |                         |        (data/nist_hipaa_crosswalk.json)
   +------------------------+-------------------------+----------------------+
                                           |
                                           v
+-----------------------------------------------------------------------------------+
|                        SECURITY CONTROLS LAYER (security_utils.py)                |
|  * HMAC-SHA256 ID Hashing (HIPAA Minimum Necessary - 45 CFR § 164.502(b))         |
|  * CSV Formula Injection (DDE) Sanitization (CWE-1236 / NIST SI-10)               |
|  * API Host Allowlisting, HTTPS Enforcement & Path Traversal Protection (CWE-22)  |
|  * Automated Security Unit Tests (tests/test_security_utils.py)                   |
+-----------------------------------------------------------------------------------+
                                           |
                                           v
+-----------------------------------------------------------------------------------+
|                      COMPLIANCE & BREACH TRIAGE ENGINE (engine/)                  |
|  * continuous_compliance_auditor.py (Evaluates Workforce, MDM, MFA, & Vendor BAAs)|
|  * hitech_breach_triage.py          (4-Factor LoProCo & Safe Harbor Triage)       |
+-----------------------------------------------------------------------------------+
                                           |
                                           v
+-----------------------------------------------------------------------------------+
|                            AUDIT DELIVERABLES (output/)                           |
|  * live_hipaa_risk_register.csv    (+ SHA-256 Integrity Hash)                     |
|  * compliance_charts.png           (Automated Severity & Safeguard Charts)        |
|  * ciso_executive_dashboard.md     (Executive Summary, CAP & POA&M Tracking)      |
|  * hitech_loproco_triage_report.md (HITECH Safe Harbor & 60-Day OCR Clock Triage) |
+-----------------------------------------------------------------------------------+
```

<br>

### Why the Crosswalk Is Separated from the Code (`data/nist_hipaa_crosswalk.json`)
Instead of hardcoding HIPAA citations and NIST control numbers inside Python `if` statements, the regulatory text lives in its own JSON file:
* **Easy to Maintain:** The Python scripts only check technical facts (for example: *Is BitLocker enabled? Is a signed BAA on file?*). If federal guidance changes or we add a new framework, we update the JSON catalog without rewriting the Python evaluation logic.
* **Built from Official NIST Data (`scripts/build_crosswalk_from_nist.py`):** Pulls from NIST's official machine-readable **Cybersecurity and Privacy Reference Tool (CPRT)** export (`SP 800-66 Rev. 2`) and merges it with the 6 active telemetry checks.
* **One Check, Multiple Audiences:** Every finding is tagged with **HIPAA**, **42 CFR Part 2**, **NIST SP 800-53 Rev. 5**, and **NIST CSF 2.0** (including `GV.SC` Supply Chain Risk Management) at the same time—giving Legal, IT Ops, and the CISO the exact references they care about.

<br>

---

## 3. Getting Started (How-To)

### Prerequisites
The project uses the **Python Standard Library** plus `matplotlib` to generate the dashboard charts, keeping external dependencies to a minimum.

* **Runtime:** Python `3.10+`
* **Standard Libraries Used:** `json`, `csv`, `hashlib`, `hmac`, `os`, `pathlib`, `urllib.parse`, `unittest`
* **Third-Party Library:** `matplotlib` (renders `compliance_charts.png`)

### Repository Structure
```text
GRCHelper/
├── .github/
│   └── workflows/
│       └── compliance_audit.yml      # GitHub Actions CI/CD & Daily Scheduled Audit
├── data/
│   ├── knowbe4_api_mock.json         # Mock Workforce, Intune MDM, & Entra ID telemetry
│   ├── tprm_api_mock.json            # Mock Third-Party Vendor BAA & SOC 2/HITRUST inventory
│   ├── nist_hipaa_crosswalk.json     # Active HIPAA / NIST crosswalk catalog
│   └── raw_nist_800_66_export.json   # Official NIST CPRT JSON export (SP 800-66 Rev. 2)
├── docs/
│   └── images/
│       └── compliance_charts.png     # Static chart preview for the README
├── engine/
│   ├── continuous_compliance_auditor.py  # Main compliance auditing & dashboard script
│   ├── hitech_breach_triage.py           # 4-Factor LoProCo & HITECH Safe Harbor triage script
│   └── security_utils.py                 # Security controls (HMAC hashing, DDE, SSRF, CWE-22)
├── scripts/
│   └── build_crosswalk_from_nist.py  # Script to build the crosswalk from NIST CPRT JSON
├── tests/
│   └── test_security_utils.py        # Unit tests for CWE-22, CWE-1236, & HMAC controls
├── output/                           # Generated reports & charts (Git-ignored for data privacy)
├── requirements.txt                  # Python dependencies
└── README.md
```

### How to Run Locally

#### Step 1: Install Dependencies
From the root directory, install `matplotlib`:

```powershell
python -m pip install -r requirements.txt
```

#### Step 2: Run the Security Unit Tests
Confirm the defensive controls (ID hashing, CSV formula sanitization, path traversal blocking, and URL validation) pass:

```powershell
python -m unittest discover -s tests -v
```

#### Step 3: (Optional) Set a Custom Salt for ID Hashing
To support the **HIPAA Minimum Necessary Standard (45 CFR § 164.502(b))**, employee IDs are hashed with `HMAC-SHA256` before being written to reports. In production, this salt comes from Azure Key Vault. Locally, you can set an environment variable:

```powershell
# PowerShell
$env:GRC_AUDIT_SALT="my-secure-organization-salt-2026"

# Linux / macOS
export GRC_AUDIT_SALT="my-secure-organization-salt-2026"
```
*(If left unset, the script defaults to a local test salt.)*

#### Step 4: (Optional) Rebuild the NIST/HIPAA Crosswalk
To rebuild `data/nist_hipaa_crosswalk.json` from the raw NIST export (`data/raw_nist_800_66_export.json`):

```powershell
python scripts/build_crosswalk_from_nist.py
```

#### Step 5: Run the Compliance Auditor & Breach Triage Scripts
Run both scripts from the repository root:

```powershell
# 1. Run the Continuous Compliance & Vendor BAA Auditor
python engine/continuous_compliance_auditor.py

# 2. Run the HITECH 4-Factor Breach Triage Script
python engine/hitech_breach_triage.py
```

**Expected Output:**
```text
Audit completed. Generated Risk Register and CISO Dashboard in /output with hash ed52cbcb0ac638a7...
HITECH 4-Factor LoProCo Triage completed. Report saved to /output with hash 4e77139db83d776a...
```

<br>

---

## 4. Sample Audit Outputs

*(Note: Following **HIPAA Data Minimization** practices, the local `output/` folder is excluded via `.gitignore` so live audit artifacts aren't committed to Git. Below are samples generated from the mock data.)*

### A. Visual Compliance Breakdown (`compliance_charts.png`)
Summary charts built for leadership and board packets:

![Executive Compliance Charts](docs/images/compliance_charts.png)

<br>

### B. Information Security Risk Register (`live_hipaa_risk_register.csv`)
Sanitized against Excel formula injection (DDE) and formatted for import into ServiceNow GRC, OneTrust, or Jira:

| Rule ID | Severity | HIPAA Citation | NIST SP 800-53 | NIST CSF 2.0 | Asset / Vendor | Core Risk Finding | Remediation Guidance (POA&M) |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `CHECK_C_ENDPOINT_ENCRYPTION` | **CRITICAL** | 45 CFR § 164.312(a)(2)(iv) | `SC-28, MP-4` | `PR.DS-01` | `id_a1c1c37ee09e` | Unencrypted endpoint accessing ePHI; voids HITECH Safe Harbor | Enforce Intune BitLocker policy & block M365 access |
| `CHECK_D_PART2_SUD_BREACH_RISK` | **CRITICAL** | 42 CFR Part 2 & 45 CFR § 164.404 | `IR-6, SC-28` | `RS.MA-01` | `id_b3cc7a729861` | Endpoint with 42 CFR Part 2 SUD access lacks disk encryption | Isolate host via Defender XDR & initiate 4-Factor LoProCo triage |
| `CHECK_E_MISSING_BAA` | **CRITICAL** | 45 CFR § 164.502(e) | `SA-9, AC-20` | `GV.SC-06` | `VEND-202` | Third-party ePHI vendor lacking signed BAA | Suspend vendor API/data access pending legal agreement |
| `CHECK_A_PHISHING_MFA` | **HIGH** | 45 CFR § 164.308(a)(5)(ii)(B) | `AT-2, IA-2(1)` | `PR.AA-01` | `id_1f07bfc30e23` | Repeat phish clicker with SUD/Part 2 access lacking strict MFA | Require remedial KnowBe4 module & apply Entra ID MFA policy |
| `CHECK_F_VENDOR_ASSURANCE` | **HIGH** | 45 CFR § 164.308(a)(1)(ii)(B) | `SA-9, RA-3` | `GV.SC-07` | `VEND-203` | Vendor processing ePHI lacks current SOC 2 / HITRUST CSF | Request updated SOC 2 Type II attestation report |
| `CHECK_B_OVERDUE_TRAINING` | **MEDIUM** | 45 CFR § 164.308(a)(5)(i) | `AT-2, AC-2` | `PR.AT-01` | `id_a1c1c37ee09e` | Annual HIPAA workforce training >14 days overdue | Escalate to manager via API; suspend EHR access after 30d |

> **Audit Log Integrity (HIPAA § 164.312(c)(1)):**  
> Every run calculates a SHA-256 hash of the exported CSV so reviewers can verify the report wasn't altered after generation:  
> `SHA-256 Digest: ed52cbcb0ac638a7c2901c5678eb178b671ec44f0b2f568a0a86377747738f6b`

<br>

### C. HITECH 4-Factor Breach Triage Report (`hitech_loproco_triage_report.md`)
Checks endpoints with ePHI and **42 CFR Part 2 SUD** access against the **HITECH Encryption Safe Harbor** and the **4-Factor LoProCo assessment (`45 CFR § 164.402`)** to see if the **60-day HHS/OCR breach reporting clock** applies:

| Asset ID | Department | Safe Harbor | Factor 1: PHI / Part 2 Scope | Factor 4: Mitigation Status | Legal Determination | 60-Day OCR Clock |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `id_1f07bfc30e23` | Clinical Admissions (SUD) | YES (Encrypted) | Secured via NIST-compliant Full-Disk Encryption (BitLocker). | Complete - Verified Intune BitLocker key escrow. | **EXEMPT (HITECH Safe Harbor - No OCR Notification Required)** | Not Triggered |
| `id_b3cc7a729861` | Clinical Admissions (SUD) | **NO (Unencrypted)** | CRITICAL (42 CFR Part 2 SUD Clinical/Diagnostic Records) | INSUFFICIENT (No BitLocker Full-Disk Encryption; Remote Wipe Pending) | **PRESUMED REPORTABLE BREACH (45 CFR § 164.404 & 42 CFR Part 2)** | **ACTIVE (60 Days)** |
| `id_a1c1c37ee09e` | Patient Billing | **NO (Unencrypted)** | HIGH (Standard ePHI / Clinical Records) | INSUFFICIENT (No BitLocker Full-Disk Encryption; Remote Wipe Pending) | **PRESUMED REPORTABLE BREACH (45 CFR § 164.404 & 42 CFR Part 2)** | **ACTIVE (60 Days)** |

<br>

### D. CISO Executive Summary (`ciso_executive_dashboard.md`)
A Markdown report summarizing open findings, Corrective Action Plans (CAP), and remediation steps.

<details>
<summary><b>▶ Click to Expand Sample CISO Executive Briefing Entry</b></summary>
<br>

#### Sample Finding from `output/ciso_executive_dashboard.md`:
* **Finding 1: [CRITICAL] 45 CFR § 164.312(a)(2)(iv) & § 164.310(d)(1) (`CHECK_C_ENDPOINT_ENCRYPTION`)**
  * **Asset / Vendor:** `id_a1c1c37ee09e` (Patient Billing)
  * **Safeguard Category:** Technical & Physical Safeguard
  * **NIST 800-53 Rev. 5 Control:** `SC-28, MP-4` | **NIST CSF 2.0:** `PR.DS-01, PR.IR-01`
  * **Issue:** Endpoint accessing ePHI is unencrypted in Intune MDM. Voids HITECH Breach Safe Harbor if lost/stolen.
  * **Remediation Plan:** Enforce Intune BitLocker XTS-AES 256 compliance policy immediately and block M365/EHR session via Conditional Access until encrypted.

</details>

<br>

---

## 5. Lab vs. Production Roadmap

This table shows how the concepts in this local lab scale up to a live production environment:

| Component | Local Lab (Current Repo) | Mid-Size Production Setup | Enterprise Scale |
| :--- | :--- | :--- | :--- |
| **Telemetry & Logs** | Local mock JSON files (`knowbe4_api_mock.json`, `tprm_api_mock.json`) run via Python & GitHub Actions. | Scheduled PowerShell or Azure Logic Apps pulling API data into restricted SharePoint/SQL tables. | Continuous log ingestion via **Microsoft Sentinel** or **Devo SIEM**, Event Hubs, and live API webhooks. |
| **Control Mapping** | Local JSON crosswalk (`nist_hipaa_crosswalk.json`) compiled from NIST CPRT data. | Shared crosswalk tables in SharePoint/Excel connected to Power BI or Power Automate. | Dedicated GRC platform (**ServiceNow GRC**, **OneTrust**, **Archer**) with automated control inheritance. |
| **PII Hashing & Secrets** | `HMAC-SHA256` hashing using a local environment variable salt in `security_utils.py`. | Restricted HR lookup tables with strict role-based access (RBAC). | Secrets managed in **Azure Key Vault** with rotation; access governed via **Entra ID PIM** and **Microsoft Purview**. |
| **Endpoint Enforcement** | Python checks flagging unencrypted devices and missing MFA in reports. | **Microsoft Intune** compliance policies paired with **Entra ID Conditional Access** to block sessions automatically. | Automated SOAR playbooks in **Microsoft Defender XDR** and **ServiceNow** isolating hosts and opening high-priority tickets. |
| **Audit Evidence Storage** | CSV Risk Register stamped with a SHA-256 hash in the Markdown report. | Reports stored in locked SharePoint libraries with version history and retention labels. | Audit logs written to **Azure Blob Immutable Storage (WORM)** to guarantee tamper-proof evidence for regulators. |

<br>

---

## 6. Regulatory & Technical Glossary

Quick reference for the healthcare regulations, NIST frameworks, and security terms used in this project:

| Term | Full Name / Authority | What It Means in Practice |
| :--- | :--- | :--- |
| **BAA** | Business Associate Agreement (45 CFR § 164.502(e)) | Contract required with any vendor that handles ePHI, holding them to HIPAA security and privacy requirements. |
| **POA&M** | Plan of Action and Milestones (NIST SP 800-53 CA-5) | A tracking list of open security findings, who owns them, how they will be fixed, and target completion dates. |
| **CAP** | Corrective Action Plan (HHS / OCR) | Formal remediation plan required after an audit finding or regulatory investigation to fix root-cause gaps. |
| **SRA** | Security Risk Assessment (45 CFR § 164.308(a)(1)(ii)(A)) | HIPAA requirement to regularly assess risks and vulnerabilities to the confidentiality, integrity, and availability of ePHI. |
| **ePHI** | Electronic Protected Health Information | Patient health, treatment, or billing records created, stored, or transmitted electronically. |
| **42 CFR Part 2** | Confidentiality of Substance Use Disorder (SUD) Records | Federal rules giving extra privacy protections to substance use disorder treatment records beyond standard HIPAA. |
| **HITECH Act** | Health Information Technology for Economic and Clinical Health Act | Federal law that established the 60-day breach notification rule and the **Safe Harbor** exemption for properly encrypted data. |
| **LoProCo** | Low Probability of Compromise (45 CFR § 164.402) | The 4-factor test used by privacy and security teams to decide if a security incident is a reportable breach. |
| **TPRM** | Third-Party Risk Management (NIST SP 800-53 SA-9 / CSF 2.0 GV.SC) | Vetting and monitoring outside vendors (checking BAAs, SOC 2 Type II reports, and HITRUST certifications). |
| **DDE** | Dynamic Data Exchange (CWE-1236 / CSV Formula Injection) | Vulnerability where formulas (`=`, `+`, `-`, `@`) inside a CSV file can trigger commands when opened in Excel. |
| **WORM** | Write Once, Read Many (45 CFR § 164.312(c)(1)) | Storage lock that prevents audit logs from being edited or deleted once written. |
