#!/usr/bin/env python3
"""
js_secrets.py — Extract secrets, endpoints, and patterns from JavaScript files.

Scans a directory of downloaded JS files and extracts:
  - API keys, tokens, credentials
  - Internal API endpoints
  - Authentication patterns (JWT, OAuth, session tokens)
  - Debug/test endpoints
  - WebSocket endpoints
  - Source maps references

Usage:
    python3 js_secrets.py \
        --js-dir /path/to/js_files/ \
        --output js_findings.json
"""

import argparse
import json
import re
import sys
from pathlib import Path


# ─── Detection Patterns ───

SECRET_PATTERNS = [
    # Generic API keys and tokens
    (r'(?i)(?:api[_-]?key|apikey|api[_-]?secret|api[_-]?token)\s*[:=]\s*["\']([^"\']{8,})["\']', "api_key"),
    (r'(?i)(?:access[_-]?token|auth[_-]?token|bearer[_-]?token)\s*[:=]\s*["\']([^"\']{8,})["\']', "access_token"),
    (r'(?i)(?:secret[_-]?key|secretkey|private[_-]?key)\s*[:=]\s*["\']([^"\']{8,})["\']', "secret_key"),

    # AWS keys
    (r'AKIA[0-9A-Z]{16}', "aws_access_key"),
    (r'(?i)aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*["\']([^"\']{20,})["\']', "aws_secret_key"),

    # Google API keys
    (r'AIza[0-9A-Za-z\-_]{35}', "google_api_key"),

    # GitHub tokens
    (r'(?:ghp|gho|ghu|ghs|ghr)_[0-9a-zA-Z]{36}', "github_token"),
    (r'(?:github[_-]?token|gh[_-]?token)\s*[:=]\s*["\']([^"\']{20,})["\']', "github_token_var"),

    # Stripe keys
    (r'(?:sk_live|pk_live|sk_test|pk_test)_[0-9a-zA-Z]{24,}', "stripe_key"),

    # Generic JWT tokens
    (r'eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_./+=]*', "jwt_token"),

    # Private keys (PEM format, inline)
    (r'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', "private_key_pem"),

    # Passwords in config
    (r'(?i)(?:password|passwd|pwd)\s*[:=]\s*["\']([^"\']{3,})["\']', "password"),
    (r'(?i)(?:db[_-]?password|database[_-]?password|db[_-]?pass)\s*[:=]\s*["\']([^"\']{3,})["\']', "db_password"),

    # Slack webhooks
    (r'https://hooks\.slack\.com/services/[A-Za-z0-9/_]+', "slack_webhook"),

    # Discord webhooks
    (r'https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9\-_]+', "discord_webhook"),

    # Firebase config — matches apiKey: "value" (key-colon-space-quote format)
    (r'(?i)firebase[a-z]*\s*[:=]\s*{[^}]*apiKey\s*:\s*["\']([^"\']+)["\']', "firebase_config"),
]

ENDPOINT_PATTERNS = [
    # API endpoint URLs
    (r'(?i)(?:https?://[^\s"\'<>]+/(?:api|graphql|v[12])/[^\s"\'<>]+)', "api_endpoint"),

    # Internal/private endpoints
    (r'(?i)(?:baseURL|base_url|BASE_URL|apiUrl|api_url|API_URL)\s*[:=]\s*["\']([^"\']+)["\']', "base_url"),
    (r'(?i)(?:apiEndpoint|api_endpoint|API_ENDPOINT|endpoint)\s*[:=]\s*["\']([^"\']+)["\']', "api_endpoint_config"),

    # GraphQL endpoints
    (r'(?i)(?:graphqlUrl|graphql_url|GRAPHQL_URL|graphqlEndpoint)\s*[:=]\s*["\']([^"\']+)["\']', "graphql_endpoint"),

    # WebSocket endpoints
    (r'(?i)wss?://[^\s"\'<>]+', "websocket_endpoint"),
    (r'(?i)(?:wsUrl|ws_url|WS_URL|socketUrl|socket_url)\s*[:=]\s*["\']([^"\']+)["\']', "websocket_config"),

    # OAuth endpoints
    (r'(?i)(?:authorizeUrl|authorize_url|tokenUrl|token_url|oauthUrl)\s*[:=]\s*["\']([^"\']+)["\']', "oauth_endpoint"),

    # Internal IPs / hostnames (non-routable)
    (r'(?i)(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})(?::\d{1,5})?(?:/[^\s"\'<>]*)?', "internal_ip"),
]

AUTH_PATTERNS = [
    # JWT decode/config
    (r'(?i)(?:jwt|token)[_-]?(?:secret|key|sign)\s*[:=]\s*["\']([^"\']{8,})["\']', "jwt_secret"),

    # OAuth client IDs
    (r'(?i)(?:client[_-]?id|clientId|CLIENT_ID|appId|APP_ID)\s*[:=]\s*["\']([^"\']{8,})["\']', "oauth_client_id"),

    # OAuth client secrets
    (r'(?i)(?:client[_-]?secret|clientSecret|CLIENT_SECRET|appSecret)\s*[:=]\s*["\']([^"\']{8,})["\']', "oauth_client_secret"),

    # Session secrets
    (r'(?i)(?:session[_-]?secret|sessionSecret|SESSION_SECRET|cookie[_-]?secret)\s*[:=]\s*["\']([^"\']{8,})["\']', "session_secret"),

    # CORS misconfiguration
    (r'(?i)Access-Control-Allow-Origin\s*:\s*\*', "cors_wildcard"),
    (r'(?i)Access-Control-Allow-Credentials\s*:\s*true', "cors_credentials"),
]

# ─── Hakluke Patterns — SPA/JS-specific endpoint and route discovery ───
# Source: Hakluke methodology. Finds framework-specific routes, WebSocket endpoints,
# postMessage origins, and Firebase configs that generic patterns miss.

HAKLUKE_PATTERNS = [
    # React Router paths
    (r'(?i)(?:path|route|to)\s*:\s*["\'](/[^"\']+)["\']', "react_route"),
    # Vue Router paths
    (r'(?i)(?:path|name)\s*:\s*["\'](/[^"\']+)["\']', "vue_route"),
    # Angular routes
    (r'(?i){path\s*:\s*["\']([^"\']+)["\']', "angular_route"),
    # WebSocket endpoints (broader pattern)
    (r'(?i)["\'](?:wss?://[^"\']+)["\']', "websocket_url"),
    # postMessage origins (cross-origin communication targets)
    (r'(?i)postMessage\s*\(\s*[^,]+,\s*["\']([^"\']+)["\']', "postmessage_origin"),
    (r'(?i)(?:allowedOrigins|allowed_origins|ALLOWED_ORIGINS)\s*[:=]\s*\[([^\]]+)\]', "cors_origins"),
    # Internal/staging hostnames in API configs
    (r'(?i)["\'](?:https?://(?:internal|private|local|staging|dev|test)[^"\']+)["\']', "internal_hostname"),
    # Hardcoded environment indicators
    (r'(?i)(?:NODE_ENV|ENVIRONMENT|APP_ENV)\s*[:=]\s*["\'](?:development|staging|testing)["\']', "non_prod_env"),
    # Feature flags revealing hidden functionality
    (r'(?i)(?:featureFlag|feature_flag|FEATURE_FLAG|isEnabled|is_enabled)\s*[:=]\s*(?:true|false|1|0)', "feature_flag"),
    # Admin/privileged route indicators
    (r'(?i)(?:isAdmin|is_admin|IS_ADMIN|isModerator|hasAccess|has_access)\s*[:=]', "privilege_check"),
]

DEBUG_PATTERNS = [
    # Console.log with sensitive data
    (r'(?i)console\.(?:log|warn|error|debug)\([^)]*(?:token|key|secret|password|credential)', "console_sensitive"),

    # Debug flags
    (r'(?i)(?:debug|DEBUG)\s*[:=]\s*(?:true|1|yes)', "debug_enabled"),
    (r'(?i)(?:verbose|VERBOSE)\s*[:=]\s*(?:true|1)', "verbose_enabled"),

    # Debug/test endpoints
    (r'(?i)(?:/debug|/test|/staging|/sandbox|/mock)[^\s"\'<>]*', "debug_endpoint"),
    (r'(?i)(?:isProduction|is_production|IS_PRODUCTION|isDev|is_dev)\s*[:=]\s*(?:false|0)', "non_production"),

    # Source maps
    (r'(?i)//# sourceMappingURL=(.+)', "source_map"),
]


def scan_file(filepath: Path, relative_path: str) -> dict:
    """Scan a single JS file for patterns."""
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except Exception as e:
        print(f"[!] Warning: could not read {relative_path}: {e}", file=sys.stderr)
        return {"file": relative_path, "error": str(e)}

    findings = {
        "file": relative_path,
        "size_bytes": len(content),
        "secrets": _scan_patterns(content, SECRET_PATTERNS, value_truncate=50),
        "endpoints": _scan_patterns(content, ENDPOINT_PATTERNS, value_truncate=200, extract_value=True),
        "auth": _scan_patterns(content, AUTH_PATTERNS, value_truncate=50, min_value_len=8),
        "hakluke": _scan_patterns(content, HAKLUKE_PATTERNS, value_truncate=200, extract_value=True),
        "debug": _scan_patterns(content, DEBUG_PATTERNS, value_truncate=200, extract_value=True),
    }
    return findings


def _scan_patterns(content: str, patterns: list, value_truncate: int = 50,
                   extract_value: bool = True, min_value_len: int = 0) -> list[dict]:
    """Generic scanner that applies patterns to content and returns structured findings."""
    results = []
    for pattern, finding_type in patterns:
        for match in re.finditer(pattern, content, re.MULTILINE):
            value = match.group(1) if (extract_value and match.lastindex) else match.group(0)
            if min_value_len and len(value) < min_value_len:
                continue
            display_value = value[:value_truncate] + "..." if len(value) > value_truncate else value
            results.append({
                "type": finding_type,
                "value_preview": display_value,
                "value": value[:value_truncate] if extract_value and len(value) <= value_truncate else None,
                "context": extract_context(content, match.start(), 80),
            })
    return results


def extract_context(content: str, position: int, context_chars: int = 80) -> str:
    """Extract surrounding context around a match position."""
    start = max(0, position - context_chars // 2)
    end = min(len(content), position + context_chars // 2)
    snippet = content[start:end].replace("\n", " ").replace("\r", " ").strip()
    # Truncate further if too long
    return snippet[:160]


def main():
    parser = argparse.ArgumentParser(description="Extract secrets and patterns from JavaScript files")
    parser.add_argument("--js-dir", required=True, help="Directory containing downloaded JS files")
    parser.add_argument("--output", required=True, help="Output JSON file")
    parser.add_argument("--min-file-size", type=int, default=100, help="Minimum file size in bytes to scan")
    args = parser.parse_args()

    js_dir = Path(args.js_dir)
    if not js_dir.is_dir():
        print(f"[-] JS directory not found: {args.js_dir}", file=sys.stderr)
        sys.exit(1)

    js_files = sorted(js_dir.glob("*.js"))
    if not js_files:
        print(f"[-] No JS files found in {args.js_dir}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Scanning {len(js_files)} JS files for secrets and patterns...")

    results = []
    total_secrets = 0
    total_endpoints = 0
    total_auth = 0
    total_hakluke = 0
    total_debug = 0

    for js_file in js_files:
        if js_file.stat().st_size < args.min_file_size:
            continue

        rel_path = js_file.name  # SHA256 hash filenames from pipeline
        findings = scan_file(js_file, rel_path)
        results.append(findings)

        total_secrets += len(findings.get("secrets", []))
        total_endpoints += len(findings.get("endpoints", []))
        total_auth += len(findings.get("auth", []))
        total_hakluke += len(findings.get("hakluke", []))
        total_debug += len(findings.get("debug", []))

    output = {
        "scan_summary": {
            "total_files_scanned": len(js_files),
            "files_with_findings": sum(
                1 for r in results
                if any(r.get(k) for k in ["secrets", "endpoints", "auth", "debug"])
            ),
            "total_secrets_found": total_secrets,
            "total_endpoints_found": total_endpoints,
            "total_auth_patterns_found": total_auth,
            "total_hakluke_patterns": total_hakluke,
            "total_debug_indicators": total_debug,
        },
        "findings": results,
    }

    with open(args.output, "w") as f:
        json.dump(output, f, indent=2)

    print(f"[+] JS analysis complete:")
    print(f"    Files scanned: {len(js_files)}")
    print(f"    Files with findings: {output['scan_summary']['files_with_findings']}")
    print(f"    Secrets: {total_secrets}")
    print(f"    Endpoints: {total_endpoints}")
    print(f"    Auth patterns: {total_auth}")
    print(f"    Debug indicators: {total_debug}")
    print(f"[+] Output: {args.output}")


if __name__ == "__main__":
    main()
