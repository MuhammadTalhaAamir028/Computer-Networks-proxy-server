"""Regenerate the TEST-ONLY self-signed certificate for localhost.

Writes tests/fixtures/test_cert.pem and test_key.pem (valid ten years).
Never use these files for anything real. Needs the `openssl` command.
"""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path
from typing import Optional

FIXTURES = Path(__file__).resolve().parent.parent / "tests" / "fixtures"
GIT_OPENSSL = Path(r"C:\Program Files\Git\usr\bin\openssl.exe")


def find_openssl() -> Optional[str]:
    """Return the openssl executable path, or None if not found."""
    found = shutil.which("openssl")
    if found:
        return found
    return str(GIT_OPENSSL) if GIT_OPENSSL.exists() else None


def main() -> int:
    """Generate the certificate and key; return a process exit code."""
    openssl = find_openssl()
    if openssl is None:
        print("openssl not found. Install Git for Windows or OpenSSL, then retry.")
        return 1
    FIXTURES.mkdir(parents=True, exist_ok=True)
    cert, key = FIXTURES / "test_cert.pem", FIXTURES / "test_key.pem"
    cmd = [
        openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes",
        "-keyout", str(key), "-out", str(cert), "-days", "3650",
        "-subj", "/O=TEST ONLY - NOT FOR PRODUCTION/CN=localhost",
        "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        print(result.stderr)
        return result.returncode
    print(f"Wrote {cert} and {key}")
    return 0


if __name__ == "__main__":
    sys.exit(main())