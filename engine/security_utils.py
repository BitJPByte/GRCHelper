"""
security_utils.py
Hardened utility functions enforcing HIPAA Minimum Necessary (45 CFR 164.502(b)),
NIST SP 800-53 SI-10 (Input Validation), and 45 CFR 164.312(c)(1) (Audit Integrity).
"""

import hashlib
import hmac
import os
from pathlib import Path
from urllib.parse import urlparse

# Strict allowlist for outbound API calls to prevent SSRF (Server-Side Request Forgery)
ALLOWED_API_HOSTS = frozenset([
    "us.api.knowbe4.com",
    "graph.microsoft.com"
])

# Dangerous characters that trigger Formula Injection (DDE) when CSVs are opened in Excel
CSV_DANGEROUS_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def validate_api_url(url: str) -> str:
    """Enforces HTTPS and strict host allowlisting to prevent SSRF & cleartext transmission (SC-8)."""
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValueError(f"Security Violation: Cleartext scheme '{parsed.scheme}' blocked. HTTPS required.")
    if parsed.hostname not in ALLOWED_API_HOSTS:
        raise ValueError(f"Security Violation: Host '{parsed.hostname}' is not in ALLOWED_API_HOSTS.")
    return url


def pseudonymize_id(raw_identifier: str) -> str:
    """
    Enforces HIPAA Minimum Necessary (45 CFR 164.502(b)) by replacing raw PII/names
    in compliance logs with a keyed HMAC-SHA256 pseudonymized token.
    """
    salt = os.getenv("GRC_AUDIT_SALT", "default-ephemeral-dev-salt-change-in-prod").encode("utf-8")
    digest = hmac.new(salt, raw_identifier.strip().lower().encode("utf-8"), hashlib.sha256).hexdigest()
    return f"id_{digest[:12]}"


def sanitize_csv_cell(value: str) -> str:
    """Prevents CSV Formula Injection (CWE-1236) when GRC analysts open Risk Registers in Excel."""
    str_val = str(value).strip()
    if str_val.startswith(CSV_DANGEROUS_PREFIXES):
        return f"'{str_val}"  # Prepend single quote to neutralize Excel formula execution
    return str_val


def generate_file_sha256(file_path: Path) -> str:
    """Generates SHA-256 hash of audit output to satisfy HIPAA 45 CFR 164.312(c)(1) Integrity."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()
