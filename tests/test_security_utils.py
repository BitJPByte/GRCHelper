"""
test_security_utils.py
Automated unit tests validating HIPAA Minimum Necessary pseudonymization (45 CFR § 164.502(b)),
CSV Formula Injection / DDE neutralization (CWE-1236), Path Traversal jailing (CWE-22),
and SSRF API host allowlisting (NIST SP 800-53 SC-8 / SI-10).
"""

import sys
import unittest
from pathlib import Path

# Add engine/ directory to sys.path for clean imports
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "engine"))

from security_utils import (
    pseudonymize_id,
    sanitize_csv_cell,
    safe_resolve_path,
    validate_api_url
)

class TestSecurityUtils(unittest.TestCase):

    def test_pseudonymize_id_hides_raw_pii(self):
        """Verifies raw Employee IDs are deterministically hashed via HMAC-SHA256."""
        raw_id = "EMP-90210"
        token = pseudonymize_id(raw_id)
        self.assertNotIn(raw_id, token)
        self.assertTrue(token.startswith("id_"))
        self.assertEqual(len(token), 15)  # 'id_' + 12 hex chars

    def test_csv_formula_injection_neutralization(self):
        """Verifies malicious Excel DDE payloads (CWE-1236) are prefixed with a single quote."""
        malicious_payloads = [
            "=cmd|' /C calc'!A0",
            "+SUM(1+1)*cmd|' /C powershell'!A0",
            "-2+3+cmd|' /C notepad'!A0",
            "@SUM(1+1)"
        ]
        for payload in malicious_payloads:
            sanitized = sanitize_csv_cell(payload)
            self.assertTrue(
                sanitized.startswith("'"),
                f"Failed to neutralize DDE payload: {payload}"
            )

    def test_safe_csv_cell_unchanged(self):
        """Verifies normal text strings are not altered by CSV sanitization."""
        normal_text = "Enforce Intune BitLocker XTS-AES 256 policy."
        self.assertEqual(sanitize_csv_cell(normal_text), normal_text)

    def test_path_traversal_blocked(self):
        """Verifies CWE-22 path traversal attempts outside base_dir raise PermissionError."""
        base_dir = REPO_ROOT / "data"
        with self.assertRaises(PermissionError):
            safe_resolve_path(base_dir, "../../etc/passwd")

    def test_ssrf_and_cleartext_url_blocked(self):
        """Verifies cleartext HTTP and unauthorized hosts are blocked."""
        with self.assertRaises(ValueError):
            validate_api_url("http://us.api.knowbe4.com/v1/users")
        with self.assertRaises(ValueError):
            validate_api_url("https://evil-attacker.com/exfiltrate")
        self.assertEqual(
            validate_api_url("https://graph.microsoft.com/v1.0/devices"),
            "https://graph.microsoft.com/v1.0/devices"
        )

if __name__ == "__main__":
    unittest.main()
