"""
continuous_compliance_auditor.py
Core GRC automation engine dynamically mapping KnowBe4, Intune, and TPRM/BAA telemetry 
against an external NIST SP 800-66 Rev. 2 / HIPAA / NIST SP 800-53 Rev. 5 Crosswalk.
"""

import json
import os
import csv
from pathlib import Path
from security_utils import (
    safe_resolve_path,
    pseudonymize_id,
    sanitize_csv_cell,
    generate_file_sha256
)

def build_finding(asset_id: str, department: str, severity: str, rule_meta: dict, issue_detail: str) -> dict:
    """Helper that binds dynamic telemetry findings to the official regulatory crosswalk."""
    return {
        "Rule_ID": rule_meta["rule_id"],
        "Asset_ID": asset_id,
        "Department": department,
        "Severity": severity,
        "Safeguard_Category": rule_meta["safeguard_category"],
        "HIPAA_Citation": rule_meta["hipaa_citation"],
        "NIST_800_53": rule_meta["nist_800_53_controls"],
        "NIST_CSF_2_0": rule_meta["nist_csf_2_0"],
        "Finding": issue_detail,
        "Remediation_POAM": rule_meta["default_remediation"]
    }

def run_audit():
    repo_root = Path(__file__).resolve().parent.parent
    data_dir = repo_root / "data"
    output_dir = repo_root / "output"
    output_dir.mkdir(exist_ok=True)

    # 1. Dynamically load the NIST SP 800-66 Rev. 2 / HIPAA Crosswalk Catalog
    crosswalk_path = safe_resolve_path(data_dir, "nist_hipaa_crosswalk.json")
    with open(crosswalk_path, "r", encoding="utf-8") as f:
        crosswalk = json.load(f)

    findings = []

    # 2. Safely load workforce telemetry data (KnowBe4 & Intune)
    telemetry_path = safe_resolve_path(data_dir, "knowbe4_api_mock.json")
    with open(telemetry_path, "r", encoding="utf-8") as f:
        users = json.load(f)

    # Evaluate workforce and endpoint compliance logic using Crosswalk lookups
    for user in users:
        anon_id = pseudonymize_id(user["employee_id"])
        dept = user["department"]

        # Check A: KnowBe4 Continuous Phishing Risk -> Identity Escalation
        if user["ephi_access"] and user["phish_failures_90d"] >= 2:
            if not user["entra_strict_mfa_enforced"]:
                rule = crosswalk["CHECK_A_PHISHING_MFA"]
                sev = "HIGH" if user["part2_sud_access"] else "MEDIUM"
                detail = f"Repeat KnowBe4 phish clicker ({user['phish_failures_90d']}x in 90d) with ePHI/Part 2 access lacks Strict Conditional Access MFA."
                findings.append(build_finding(anon_id, dept, sev, rule, detail))

        # Check B: Delinquent Annual Training Gatekeeper
        if user["ephi_access"] and user["annual_hipaa_training_status"] == "Overdue" and user["days_overdue"] > 14:
            rule = crosswalk["CHECK_B_OVERDUE_TRAINING"]
            detail = f"Mandatory workforce HIPAA/HITECH training is {user['days_overdue']} days overdue while retaining active ePHI access."
            findings.append(build_finding(anon_id, dept, "MEDIUM", rule, detail))

        # Check C: Intune MDM Encryption & HITECH Safe Harbor Check
        if user["ephi_access"] and not user["intune_device_encrypted"]:
            rule = crosswalk["CHECK_C_ENDPOINT_ENCRYPTION"]
            detail = "Endpoint accessing ePHI is unencrypted in Intune MDM. Voids HITECH Breach Safe Harbor if lost/stolen."
            findings.append(build_finding(anon_id, dept, "CRITICAL", rule, detail))

        # Check D: 42 CFR Part 2 (SUD Records) & HITECH Breach Triage
        if user.get("part2_sud_access") and not user.get("intune_device_encrypted"):
            rule = crosswalk["CHECK_D_PART2_SUD_BREACH_RISK"]
            detail = "Endpoint accessing highly sensitive 42 CFR Part 2 Substance Use Disorder records lacks full-disk encryption. Unencrypted loss constitutes a reportable HITECH breach triggering mandatory HHS/OCR notification within 60 days."
            findings.append(build_finding(anon_id, dept, "CRITICAL", rule, detail))

    # 3. Safely load Third-Party Risk Management (TPRM / BAA) telemetry data
    tprm_path = safe_resolve_path(data_dir, "tprm_api_mock.json")
    with open(tprm_path, "r", encoding="utf-8") as f:
        vendors = json.load(f)

    # Evaluate vendor TPRM and BAA compliance logic using Crosswalk lookups
    for vendor in vendors:
        vendor_id = vendor["vendor_id"]
        vendor_name = vendor["vendor_name"]
        dept_label = f"Vendor: {vendor_name}"

        # Check E: Missing Business Associate Agreement (BAA) for ePHI Vendor
        if vendor["phi_access"] and not vendor["baa_signed"]:
            rule = crosswalk["CHECK_E_MISSING_BAA"]
            detail = f"Third-party vendor '{vendor_name}' has active ePHI access but lacks an executed Business Associate Agreement (BAA)."
            findings.append(build_finding(vendor_id, dept_label, "CRITICAL", rule, detail))

        # Check F: Uncertified Third-Party Vendor Security Posture (SOC 2 / HITRUST)
        if vendor["phi_access"] and not vendor["soc2_hitrust_certified"]:
            rule = crosswalk["CHECK_F_VENDOR_ASSURANCE"]
            detail = f"Vendor '{vendor_name}' processing ePHI lacks a valid annual SOC 2 Type II or HITRUST CSF certification (Assessment age: {vendor['days_since_assessment']} days)."
            findings.append(build_finding(vendor_id, dept_label, "HIGH", rule, detail))

    # 4. Output Sanitized CSV Risk Register (POA&M)
    csv_path = safe_resolve_path(output_dir, "live_hipaa_risk_register.csv")
    csv_headers = [
        "Rule_ID", "Asset_ID", "Department", "Severity", "Safeguard_Category",
        "HIPAA_Citation", "NIST_800_53", "NIST_CSF_2_0", "Finding", "Remediation_POAM"
    ]
    with open(csv_path, "w", newline="", encoding="utf-8") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(csv_headers)
        for item in findings:
            sanitized_row = [sanitize_csv_cell(str(item[h])) for h in csv_headers]
            writer.writerow(sanitized_row)

    # 5. Generate SHA-256 Integrity Hash for HIPAA § 164.312(c)(1) Compliance
    file_hash = generate_file_sha256(csv_path)

    import matplotlib.pyplot as plt

    # 6. Generate Compliance Visual Charts
    severities = [f["Severity"] for f in findings]
    sev_counts = {sev: severities.count(sev) for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]}
    sev_counts = {k: v for k, v in sev_counts.items() if v > 0}

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(10, 4))
    ax1.bar(sev_counts.keys(), sev_counts.values(), color=['#d9534f', '#f0ad4e', '#5bc0de'])
    ax1.set_title("Open Findings by Severity", fontweight="bold")
    ax1.set_ylabel("Count")

    admin_count = sum(1 for f in findings if "Administrative" in f["Safeguard_Category"])
    tech_phys_count = len(findings) - admin_count

    ax2.pie([admin_count, tech_phys_count], labels=["Admin / TPRM Safeguards", "Tech / Physical Safeguards"], 
            autopct="%1.0f%%", colors=["#0275d8", "#5cb85c"], startangle=90)
    ax2.set_title("Findings by HIPAA Category", fontweight="bold")
    plt.tight_layout()
    chart_path = output_dir / "compliance_charts.png"
    plt.savefig(chart_path, dpi=300)
    plt.close()

    # 7. Generate CISO Executive Dashboard Markdown Report with Table and Charts
    md_path = safe_resolve_path(output_dir, "ciso_executive_dashboard.md")
    with open(md_path, "w", encoding="utf-8") as md_file:
        md_file.write(f"# BitByte CISO Executive Compliance Dashboard\n\n")
        md_file.write(f"**Audit Status:** Completed Successfully  \n")
        md_file.write(f"**Total Open Findings:** {len(findings)}  \n")
        md_file.write(f"**Audit Artifact SHA-256 Digest (HIPAA § 164.312(c)(1)):** `{file_hash}`\n\n")
        
        # Embed Visual Charts
        md_file.write("## Executive Visual Overview\n")
        md_file.write("![Compliance Charts](compliance_charts.png)\n\n")

        # Embed Executive Summary Table
        md_file.write("## Executive Findings Summary\n\n")
        md_file.write("| Severity | Rule ID | HIPAA Citation | NIST 800-53 | NIST CSF 2.0 | Department / Asset | Core Risk & Remediation Summary |\n")
        md_file.write("| :--- | :--- | :--- | :--- | :--- | :--- | :--- |\n")
        for item in findings:
            md_file.write(f"| **{item['Severity']}** | `{item['Rule_ID']}` | {item['HIPAA_Citation']} | `{item['NIST_800_53']}` | `{item['NIST_CSF_2_0']}` | {item['Department']} | {item['Finding']} *Action: {item['Remediation_POAM']}* |\n")

        md_file.write("\n## Detailed POA&M Breakdown\n\n")
        for idx, item in enumerate(findings, 1):
            md_file.write(f"### Finding {idx}: [{item['Severity']}] {item['HIPAA_Citation']} ({item['Rule_ID']})\n")
            md_file.write(f"- **Asset / Vendor:** `{item['Asset_ID']}` ({item['Department']})\n")
            md_file.write(f"- **Safeguard Category:** {item['Safeguard_Category']}\n")
            md_file.write(f"- **NIST 800-53 Rev. 5 Control:** `{item['NIST_800_53']}` | **NIST CSF 2.0:** `{item['NIST_CSF_2_0']}`\n")
            md_file.write(f"- **Issue:** {item['Finding']}\n")
            md_file.write(f"- **Remediation Plan:** {item['Remediation_POAM']}\n\n")

    print(f"Audit completed. Generated Risk Register and CISO Dashboard in /output with hash {file_hash[:16]}...")

if __name__ == "__main__":
    run_audit()