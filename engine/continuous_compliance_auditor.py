"""
continuous_compliance_auditor.py
Core GRC automation engine mapping KnowBe4 and Intune telemetry
to HIPAA Security Rule (45 CFR Part 164) and NIST SP 800-53 Rev. 5 controls.
"""

import json
import os
from pathlib import Path
from security_utils import (
    safe_resolve_path,
    pseudonymize_id,
    sanitize_csv_cell,
    generate_file_sha256
)

def run_audit():
    repo_root = Path(__file__).resolve().parent.parent
    data_dir = repo_root / "data"
    output_dir = repo_root / "output"
    output_dir.mkdir(exist_ok=True)

    # 1. Safely load mock telemetry data
    telemetry_path = safe_resolve_path(data_dir, "knowbe4_api_mock.json")
    with open(telemetry_path, "r", encoding="utf-8") as f:
        users = json.load(f)

    findings = []

    # 2. Evaluate workforce and endpoint compliance logic
    for user in users:
        anon_id = pseudonymize_id(user["employee_id"])
        dept = user["department"]

        # Check A: KnowBe4 Continuous Phishing Risk -> Identity Escalation
        if user["ephi_access"] and user["phish_failures_90d"] >= 2:
            if not user["entra_strict_mfa_enforced"]:
                findings.append({
                    "Asset_ID": anon_id,
                    "Department": dept,
                    "Severity": "HIGH" if user["part2_sud_access"] else "MEDIUM",
                    "HIPAA_Citation": "45 CFR § 164.308(a)(5)(ii)(B)",
                    "NIST_800_53": "AT-2, IA-2(1), SI-3",
                    "Finding": f"Repeat KnowBe4 phish clicker ({user['phish_failures_90d']}x in 90d) with ePHI/Part 2 access lacks Strict Conditional Access MFA.",
                    "Remediation_POAM": "Enroll in KnowBe4 remedial training & enforce Entra ID High-Risk Clinical MFA policy."
                })

        # Check B: Delinquent Annual Training Gatekeeper
        if user["ephi_access"] and user["annual_hipaa_training_status"] == "Overdue" and user["days_overdue"] > 14:
            findings.append({
                "Asset_ID": anon_id,
                "Department": dept,
                "Severity": "MEDIUM",
                "HIPAA_Citation": "45 CFR § 164.308(a)(5)(i)",
                "NIST_800_53": "AT-2, AC-2",
                "Finding": f"Mandatory workforce HIPAA/HITECH training is {user['days_overdue']} days overdue while retaining active ePHI access.",
                "Remediation_POAM": "Trigger manager alert via KnowBe4 API; suspend EHR group access if past 30 days."
            })

        # Check C: Intune MDM Encryption & HITECH Safe Harbor Check
        if user["ephi_access"] and not user["intune_device_encrypted"]:
            findings.append({
                "Asset_ID": anon_id,
                "Department": dept,
                "Severity": "CRITICAL",
                "HIPAA_Citation": "45 CFR § 164.312(a)(2)(iv) & § 164.310(d)(1)",
                "NIST_800_53": "SC-28, MP-4",
                "Finding": "Endpoint accessing ePHI is unencrypted in Intune MDM. Voids HITECH Breach Safe Harbor if lost/stolen.",
                "Remediation_POAM": "Enforce Intune BitLocker compliance policy immediately and block M365 session until encrypted."
            })

    # 3. Output Sanitized CSV Risk Register (POA&M)
    csv_path = safe_resolve_path(output_dir, "live_hipaa_risk_register.csv")
    csv_headers = ["Asset_ID", "Department", "Severity", "HIPAA_Citation", "NIST_800_53", "Finding", "Remediation_POAM"]

    with open(csv_path, "w", newline="", encoding="utf-8") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(csv_headers)
        for item in findings:
            sanitized_row = [sanitize_csv_cell(str(item[h])) for h in csv_headers]
            writer.writerow(sanitized_row)

    # 4. Generate SHA-256 Integrity Hash for HIPAA 164.312(c)(1) Compliance
    file_hash = generate_file_sha256(csv_path)
    
    # 5. Generate CISO Executive Dashboard Markdown Report
    md_path = safe_resolve_path(output_dir, "ciso_executive_dashboard.md")
    with open(md_path, "w", encoding="utf-8") as md_file:
        md_file.write(f"# BitByte CISO Executive Compliance Dashboard\n\n")
        md_file.write(f"**Audit Status:** Completed Successfully  \n")
        md_file.write(f"**Total Open Findings:** {len(findings)}  \n")
        md_file.write(f"**Audit Artifact SHA-256 Digest (HIPAA 164.312(c)(1)):** `{file_hash}`\n\n")
        md_file.write("## Active Risk Items & POA&M\n\n")
        for idx, item in enumerate(findings, 1):
            md_file.write(f"### Finding {idx}: [{item['Severity']}] {item['HIPAA_Citation']}\n")
            md_file.write(f"- **Asset:** `{item['Asset_ID']}` ({item['Department']})\n")
            md_file.write(f"- **NIST 800-53 Control:** `{item['NIST_800_53']}`\n")
            md_file.write(f"- **Issue:** {item['Finding']}\n")
            md_file.write(f"- **Remediation Plan:** {item['Remediation_POAM']}\n\n")

    print(f"Audit completed. Generated Risk Register and CISO Dashboard in /output with hash {file_hash[:16]}...")

if __name__ == "__main__":
    run_audit()
