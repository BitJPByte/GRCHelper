"""
build_crosswalk_from_nist.py
Automated parser converting raw NIST CPRT (Cybersecurity and Privacy Reference Tool) 
JSON exports directly into the engine's active nist_hipaa_crosswalk.json catalog.
"""

import json
from pathlib import Path

def generate_crosswalk_from_nist_json(raw_json_path: Path, output_json_path: Path):
    """
    Parses a raw NIST CPRT JSON export (or custom catalog export) and extracts 
    the active rules mapped to HIPAA, NIST SP 800-53 Rev. 5, and NIST CSF 2.0.
    """
    with open(raw_json_path, mode="r", encoding="utf-8") as f:
        raw_data = json.load(f)

    crosswalk_catalog = {}

    # Case 1: NIST CPRT native schema with top-level 'elements' or 'documents'
    if isinstance(raw_data, dict) and "elements" in raw_data:
        elements = raw_data.get("elements", [])
        for elem in elements:
            rule_id = elem.get("identifier") or elem.get("id") or elem.get("element_id")
            if not rule_id:
                continue
            crosswalk_catalog[rule_id] = {
                "rule_id": rule_id,
                "rule_name": elem.get("title") or elem.get("name", "NIST Control"),
                "safeguard_category": elem.get("category", "Safeguard"),
                "hipaa_citation": elem.get("hipaa_citation", "45 CFR Part 164"),
                "nist_800_53_controls": elem.get("sp_800_53", rule_id),
                "nist_csf_2_0": elem.get("csf_2_0", "N/A"),
                "default_remediation": elem.get("remediation", "Enforce baseline control.")
            }
    # Case 2: List of rule objects (standard tabular export dumped to JSON)
    elif isinstance(raw_data, list):
        for item in raw_data:
            rule_id = item.get("Rule_ID") or item.get("rule_id") or item.get("id")
            if not rule_id:
                continue
            crosswalk_catalog[rule_id] = {
                "rule_id": rule_id,
                "rule_name": item.get("Rule_Name") or item.get("rule_name", ""),
                "safeguard_category": item.get("Safeguard_Category") or item.get("safeguard_category", ""),
                "hipaa_citation": item.get("HIPAA_Citation") or item.get("hipaa_citation", ""),
                "nist_800_53_controls": item.get("NIST_800_53") or item.get("nist_800_53", ""),
                "nist_csf_2_0": item.get("NIST_CSF_2_0") or item.get("nist_csf_2_0", ""),
                "default_remediation": item.get("Remediation_Guidance") or item.get("default_remediation", "")
            }
    # Case 3: Already keyed dictionary
    elif isinstance(raw_data, dict):
        crosswalk_catalog = raw_data

    with open(output_json_path, mode="w", encoding="utf-8") as out:
        json.dump(crosswalk_catalog, out, indent=2)

    print(f"[+] Successfully compiled {len(crosswalk_catalog)} controls into {output_json_path.name}")

if __name__ == "__main__":
    repo_root = Path(__file__).resolve().parent.parent
    raw_file = repo_root / "data" / "raw_nist_800_66_export.json"
    target_json = repo_root / "data" / "nist_hipaa_crosswalk.json"

    if raw_file.exists():
        generate_crosswalk_from_nist_json(raw_file, target_json)
    else:
        print(f"[*] Drop the raw NIST JSON export at: {raw_file}")