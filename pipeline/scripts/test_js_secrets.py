#!/usr/bin/env python3
"""
Smoke tests for js_secrets.py regex patterns.

Run with: python3 test_js_secrets.py
"""

import json
import sys
from pathlib import Path
from tempfile import NamedTemporaryFile

# Import the module under test
sys.path.insert(0, str(Path(__file__).parent))
from js_secrets import scan_file, _scan_patterns, SECRET_PATTERNS, ENDPOINT_PATTERNS, AUTH_PATTERNS, DEBUG_PATTERNS

TESTS = []

def test(name):
    """Decorator to register test functions."""
    def decorator(fn):
        TESTS.append((name, fn))
        return fn
    return decorator


@test("AWS access key detection")
def test_aws_key():
    content = 'const AWS_KEY = "AKIAIOSFODNN7EXAMPLE";'
    results = _scan_patterns(content, SECRET_PATTERNS)
    assert any(r["type"] == "aws_access_key" for r in results), "AWS key not detected"


@test("GitHub token detection")
def test_github_token():
    content = 'export GITHUB_TOKEN=ghp_abcdefghijklmnopqrstuvwxyz0123456789'
    results = _scan_patterns(content, SECRET_PATTERNS)
    assert any(r["type"] == "github_token" for r in results), "GitHub token not detected"


@test("Stripe live key detection")
def test_stripe_key():
    content = 'const STRIPE_KEY = "pk_test_abcdefghijklmnopqrstuvwx";'
    results = _scan_patterns(content, SECRET_PATTERNS)
    assert any(r["type"] == "stripe_key" for r in results), "Stripe key not detected"


@test("JWT token detection")
def test_jwt_token():
    content = 'const token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";'
    results = _scan_patterns(content, SECRET_PATTERNS)
    assert any(r["type"] == "jwt_token" for r in results), "JWT token not detected"


@test("Password in config detection")
def test_password_config():
    content = 'const config = { password: "supersecret123" };'
    results = _scan_patterns(content, SECRET_PATTERNS)
    assert any(r["type"] == "password" for r in results), "Password not detected"


@test("API endpoint URL detection")
def test_api_endpoint():
    content = 'fetch("https://api.example.com/v1/users")'
    results = _scan_patterns(content, ENDPOINT_PATTERNS)
    assert any(r["type"] == "api_endpoint" for r in results), "API endpoint not detected"


@test("Internal IP detection")
def test_internal_ip():
    content = 'const API_URL = "http://10.0.1.50:3000/api";'
    results = _scan_patterns(content, ENDPOINT_PATTERNS)
    assert any(r["type"] == "internal_ip" for r in results), "Internal IP not detected"


@test("JWT secret detection")
def test_jwt_secret():
    content = 'const JWT_SECRET = "super-secret-signing-key-2024";'
    results = _scan_patterns(content, AUTH_PATTERNS)
    assert any(r["type"] == "jwt_secret" for r in results), "JWT secret not detected"


@test("OAuth client ID detection")
def test_oauth_client_id():
    content = 'const CLIENT_ID = "abc123def456ghijklm";'
    results = _scan_patterns(content, AUTH_PATTERNS)
    assert any(r["type"] == "oauth_client_id" for r in results), "OAuth client ID not detected"


@test("Debug flag detection")
def test_debug_flag():
    content = 'const DEBUG = true;'
    results = _scan_patterns(content, DEBUG_PATTERNS)
    assert any(r["type"] == "debug_enabled" for r in results), "Debug flag not detected"


@test("Source map detection")
def test_source_map():
    content = '//# sourceMappingURL=main.abc123.js.map'
    results = _scan_patterns(content, DEBUG_PATTERNS)
    assert any(r["type"] == "source_map" for r in results), "Source map not detected"


@test("scan_file integration with temp file")
def test_scan_file_integration():
    js_content = """
    const API_KEY = "pk_test_abcdefghijklmnopqrstuvwx";
    const API_URL = "https://api.internal.example.com/v2/data";
    const DEBUG = true;
    """
    with NamedTemporaryFile(mode="w", suffix=".js", delete=False) as f:
        f.write(js_content)
        tmp_path = f.name

    try:
        findings = scan_file(Path(tmp_path), "test.js")
        assert "error" not in findings, f"scan_file returned error: {findings.get('error')}"
        assert len(findings["secrets"]) >= 1, "No secrets found"
        assert len(findings["endpoints"]) >= 1, "No endpoints found"
        assert len(findings["debug"]) >= 1, "No debug patterns found"
    finally:
        Path(tmp_path).unlink()


@test("Empty file returns no findings")
def test_empty_file():
    with NamedTemporaryFile(mode="w", suffix=".js", delete=False) as f:
        f.write("")
        tmp_path = f.name
    try:
        findings = scan_file(Path(tmp_path), "empty.js")
        assert "error" not in findings
        assert findings["size_bytes"] == 0
    finally:
        Path(tmp_path).unlink()


@test("Short password values are skipped")
def test_short_auth_values():
    content = 'const jwt_secret = "abc";'
    results = _scan_patterns(content, AUTH_PATTERNS, min_value_len=8)
    assert len(results) == 0, "Short JWT secret should be filtered by min_value_len"


@test("Private key PEM detection")
def test_private_key():
    content = 'const key = `-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...`;'
    results = _scan_patterns(content, SECRET_PATTERNS)
    assert any(r["type"] == "private_key_pem" for r in results), "Private key not detected"


@test("Firebase config detection")
def test_firebase_config():
    content = 'const firebaseConfig = { apiKey: "test-api-key-not-real" };'
    results = _scan_patterns(content, SECRET_PATTERNS)
    assert any(r["type"] == "firebase_config" for r in results), "Firebase config not detected"


# ─── Runner ───

if __name__ == "__main__":
    passed = 0
    failed = 0
    for name, fn in TESTS:
        try:
            fn()
            print(f"  [PASS] {name}")
            passed += 1
        except AssertionError as e:
            print(f"  [FAIL] {name}: {e}")
            failed += 1
        except Exception as e:
            print(f"  [ERROR] {name}: {e}")
            failed += 1

    print(f"\n  {passed} passed, {failed} failed of {len(TESTS)} tests")
    sys.exit(0 if failed == 0 else 1)