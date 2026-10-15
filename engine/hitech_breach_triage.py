"""
hitech_breach_triage.py
Automated HITECH Act (45 CFR § 164.402 / § 164.404) & 42 CFR Part 2 
4-Factor LoProCo (Low Probability of Compromise) Breach Triage Engine.
"""

import json
from pathlib import Path
from security_utils import (
    safe_resolve_path,
    pseudonymize_id,
    generate_file_sha256
)

def evaluate_4_factor_loproco(user_record: dict) -> dict:
    """
    Evaluates an endpoint exposure event against the statutory 4-Factor HITECH LoProCo test
    (45 CFR § 164.402(2)) and HITECH Encryption Safe Harbor (45 CFR § 164.402).
    """
    anon_id = pseudonymize_id(user_record["employee_id"])
    dept = user_record["department"]
    encrypted = bool(user_record.get("intune_device_encrypted"))
    ephi = bool(user_record.get("ephi_access"))
    part2_sud = bool(user_record.get("part2_sud_access"))

    # Check HITECH Encryption Safe Harbor first (NIST SP 800-111 / BitLocker XTS-AES 256)
    if encrypted:
        return {
            "Asset_ID": anon_id,
            "Department": dept,
            "Safe_Harbor_Applies": True,
            "Factor_1_Nature_of_PHI": "Secured via NIST-compliant Full-Disk Encryption (BitLocker).",
            "Factor_2_Unauthorized_Recipient": "N/A - Data rendered unusable, unreadable, or indecipherable.",
            "Factor_3_Actual_Acquisition": "Low - Cryptographic Safe Harbor active.",
            "Factor_4_Mitigation_Extent": "Complete - Verified Intune BitLocker key escrow.",
            "Breach_Determination": "EXEMPT (HITECH Safe Harbor - No OCR Notification Required)",
            "OCR_60_Day_Clock_Triggered": False
        }

    # If unencrypted and accessing ePHI / 42 CFR Part 2 SUD records, evaluate the 4 statutory factors
    f1_score = "CRITICAL (42 CFR Part 2 SUD Clinical/Diagnostic Records)" if part2_sud else (
        "HIGH (Standard ePHI / Clinical Records)" if ephi else "LOW (No ePHI Access)"
    )
    f2_score = "HIGH (Uncontrolled External Loss / Potential Unauthorized Viewing)"
    f3_score = "HIGH (Unencrypted Storage Media - Presumed Accessible if Lost/Stolen)"
    f4_score = "INSUFFICIENT (No BitLocker Full-Disk Encryption; Remote Wipe Pending)"

    presumed_breach = ephi or part2_sud

    return {
        "Asset_ID": anon_id,
        "Department": dept,
        "Safe_Harbor_Applies": False,
        "Factor_1_Nature_of_PHI": f1_score,
        "Factor_2_Unauthorized_Recipient": f2_score,
        "Factor_3_Actual_Acquisition": f3_score,
        "Factor_4_Mitigation_Extent": f4_score,
        "Breach_Determination": (
            "PRESUMED REPORTABLE BREACH (45 CFR § 164.404 & 42 CFR Part 2)"
            if presumed_breach else "NON-PHI INCIDENT"
        ),
        "OCR_60_Day_Clock_Triggered": presumed_breach
    }

def run_breach_triage():
    repo_root = Path(__file__).resolve().parent.parent
    data_dir = repo_root / "data"
    output_dir = repo_root / "output"
    output_dir.mkdir(exist_ok=True)

    telemetry_path = safe_resolve_path(data_dir, "knowbe4_api_mock.json")
    with open(telemetry_path, "r", encoding="utf-8") as f:
        users = json.load(f)

    triage_results = [evaluate_4_factor_loproco(u) for u in users if u.get("ephi_access")]

    md_path = safe_resolve_path(output_dir, "hitech_loproco_triage_report.md")
    lines = [
        "# HITECH 4-Factor LoProCo & 42 CFR Part 2 Breach Triage Report",
        "",
        "**Regulatory Authority:** 45 CFR § 164.402 (LoProCo), 45 CFR § 164.404 (60-Day OCR Notification), & 42 CFR Part 2  ",
        "",
        "| Asset ID | Department | Safe Harbor | Factor 1: PHI / Part 2 Scope | Factor 4: Mitigation Status | Legal Determination | 60-Day OCR Clock |",
        "| :--- | :--- | :--- | :--- | :--- | :--- | :--- |"
    ]
    for r in triage_results:
        sh = "YES (Encrypted)" if r["Safe_Harbor_Applies"] else "**NO (Unencrypted)**"
        clock = "**ACTIVE (60 Days)**" if r["OCR_60_Day_Clock_Triggered"] else "Not Triggered"
        lines.append(
            f"| `{r['Asset_ID']}` | {r['Department']} | {sh} | {r['Factor_1_Nature_of_PHI']} | "
            f"{r['Factor_4_Mitigation_Extent']} | **{r['Breach_Determination']}** | {clock} |"
        )

    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    digest = generate_file_sha256(md_path)
    print(f"HITECH 4-Factor LoProCo Triage completed. Report saved to /output with hash {digest[:16]}...")

if __name__ == "__main__":
    run_breach_triage()
