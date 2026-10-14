"""
build_crosswalk_from_nist.py
Automated parser converting raw NIST CPRT (Cybersecurity and Privacy Reference Tool) 
JSON exports into the engine's active nist_hipaa_crosswalk.json catalog, while preserving 
and binding the 6 core continuous telemetry rules (CHECK_A through CHECK_F).
"""

import json
from pathlib import Path

# Baseline automated engine rules mapped to official NIST SP 800-66 Rev. 2 / SP 800-53 Rev. 5 / CSF 2.0
CORE_ENGINE_RULES = {
    "CHECK_A_PHISHING_MFA": {
        "rule_id": "CHECK_A_PHISHING_MFA",
        "rule_name": "High-Risk Clinical Identity & Phishing Escalation",
        "safeguard_category": "Administrative & Technical Safeguard",
        "hipaa_citation": "45 CFR § 164.308(a)(5)(ii)(B) & § 164.312(d)",
        "nist_800_53_controls": "AT-2, IA-2(1), SI-3",
        "nist_csf_2_0": "PR.AT-01, PR.AA-01",
        "default_remediation": "Enroll in KnowBe4 remedial training & enforce Entra ID High-Risk Clinical Phishing-Resistant MFA policy."
    },
    "CHECK_B_OVERDUE_TRAINING": {
        "rule_id": "CHECK_B_OVERDUE_TRAINING",
        "rule_name": "Delinquent Annual HIPAA/HITECH Workforce Training Gatekeeper",
        "safeguard_category": "Administrative Safeguard",
        "hipaa_citation": "45 CFR § 164.308(a)(5)(i)",
        "nist_800_53_controls": "AT-2, AC-2",
        "nist_csf_2_0": "PR.AT-01, PR.AA-05",
        "default_remediation": "Trigger manager escalation via KnowBe4 API; suspend EHR/ePHI security group membership if past 30 days."
    },
    "CHECK_C_ENDPOINT_ENCRYPTION": {
        "rule_id": "CHECK_C_ENDPOINT_ENCRYPTION",
        "rule_name": "Intune MDM Full-Disk Encryption & HITECH Safe Harbor Verification",
        "safeguard_category": "Technical & Physical Safeguard",
        "hipaa_citation": "45 CFR § 164.312(a)(2)(iv) & § 164.310(d)(1)",
        "nist_800_53_controls": "SC-28, MP-4",
        "nist_csf_2_0": "PR.DS-01, PR.IR-01",
        "default_remediation": "Enforce Intune BitLocker XTS-AES 256 compliance policy immediately and block M365/EHR session via Conditional Access until encrypted."
    },
    "CHECK_D_PART2_SUD_BREACH_RISK": {
        "rule_id": "CHECK_D_PART2_SUD_BREACH_RISK",
        "rule_name": "42 CFR Part 2 Substance Use Disorder (SUD) Unencrypted Endpoint Exposure",
        "safeguard_category": "Breach Triage & Technical Safeguard",
        "hipaa_citation": "42 CFR Part 2 & HITECH Act (45 CFR § 164.404)",
        "nist_800_53_controls": "IR-6, SC-28, AC-3",
        "nist_csf_2_0": "RS.MA-01, PR.DS-01",
        "default_remediation": "Isolate endpoint via Intune/Defender XDR, trigger remote BitLocker escrow verification, and initiate 4-Factor LoProCo Incident Response triage."
    },
    "CHECK_E_MISSING_BAA": {
        "rule_id": "CHECK_E_MISSING_BAA",
        "rule_name": "Third-Party ePHI Vendor Missing Executed Business Associate Agreement (BAA)",
        "safeguard_category": "Administrative / TPRM Safeguard",
        "hipaa_citation": "45 CFR § 164.502(e) & § 164.504(e)",
        "nist_800_53_controls": "SA-9, AC-20, SR-3",
        "nist_csf_2_0": "GV.SC-06, GV.SC-07",
        "default_remediation": "Immediately suspend vendor API/data integration until Legal executes a formal HIPAA/Part 2 Business Associate Agreement."
    },
    "CHECK_F_VENDOR_ASSURANCE": {
        "rule_id": "CHECK_F_VENDOR_ASSURANCE",
        "rule_name": "Uncertified Third-Party Vendor Security Posture (Missing SOC 2 / HITRUST)",
        "safeguard_category": "Administrative / TPRM Safeguard",
        "hipaa_citation": "45 CFR § 164.308(a)(1)(ii)(B) & § 164.308(b)(1)",
        "nist_800_53_controls": "SA-9, RA-3, CA-2",
        "nist_csf_2_0": "GV.SC-07, ID.RA-01",
        "default_remediation": "Request updated SOC 2 Type II or HITRUST CSF attestation report or initiate formal TPRM security exception review."
    }
}

def extract_element_records(raw_data):
    """Safely extracts dictionary items whether CPRT elements is a dict, list of dicts, or list of strings."""
    items = []
    elements_raw = None

    if isinstance(raw_data, dict):
        if "elements" in raw_data:
            elements_raw = raw_data["elements"]
        elif "response" in raw_data and isinstance(raw_data["response"], dict):
            elements_raw = raw_data["response"].get("elements")
    elif isinstance(raw_data, list):
        elements_raw = raw_data

    if isinstance(elements_raw, dict):
        for k, v in elements_raw.items():
            if isinstance(v, dict):
                v_copy = dict(v)
                v_copy.setdefault("identifier", k)
                items.append(v_copy)
            elif isinstance(v, str):
                items.append({"identifier": k, "name": v})
    elif isinstance(elements_raw, list):
        for elem in elements_raw:
            if isinstance(elem, dict):
                items.append(elem)
            elif isinstance(elem, str):
                items.append({"identifier": elem, "name": elem})

    return items

def generate_crosswalk_from_nist_json(raw_json_path: Path, output_json_path: Path):
    """
    Always retains the 6 baseline telemetry rules (CHECK_A through CHECK_F) 
    and merges any additional official NIST CPRT controls if present.
    """
    crosswalk_catalog = dict(CORE_ENGINE_RULES)

    if raw_json_path.exists():
        try:
            with open(raw_json_path, mode="r", encoding="utf-8") as f:
                raw_data = json.load(f)

            elements = extract_element_records(raw_data)
            for elem in elements:
                rule_id = (
                    elem.get("element_identifier")
                    or elem.get("identifier")
                    or elem.get("id")
                    or elem.get("Rule_ID")
                )
                if not rule_id or rule_id in crosswalk_catalog:
                    continue

                crosswalk_catalog[str(rule_id)] = {
                    "rule_id": str(rule_id),
                    "rule_name": elem.get("title") or elem.get("name") or elem.get("Rule_Name", "NIST Control"),
                    "safeguard_category": elem.get("element_type") or elem.get("category") or elem.get("Safeguard_Category", "NIST SP 800-66 Rev. 2 Reference"),
                    "hipaa_citation": elem.get("hipaa_citation") or elem.get("HIPAA_Citation", str(rule_id)),
                    "nist_800_53_controls": elem.get("sp_800_53") or elem.get("NIST_800_53", str(rule_id)),
                    "nist_csf_2_0": elem.get("csf_2_0") or elem.get("NIST_CSF_2_0", "N/A"),
                    "default_remediation": elem.get("text") or elem.get("Remediation_Guidance") or elem.get("default_remediation", "Enforce NIST SP 800-66 Rev. 2 control baseline.")
                }
        except Exception as e:
            print(f"[!] Warning parsing raw export: {e}. Preserving core telemetry rules.")

    output_json_path.parent.mkdir(exist_ok=True, parents=True)
    with open(output_json_path, mode="w", encoding="utf-8") as out:
        json.dump(crosswalk_catalog, out, indent=2)

    print(f"[+] Successfully compiled {len(crosswalk_catalog)} controls (including 6 active telemetry rules) into {output_json_path.name}")

if __name__ == "__main__":
    repo_root = Path(__file__).resolve().parent.parent
    raw_file = repo_root / "data" / "raw_nist_800_66_export.json"
    target_json = repo_root / "data" / "nist_hipaa_crosswalk.json"

    generate_crosswalk_from_nist_json(raw_file, target_json)