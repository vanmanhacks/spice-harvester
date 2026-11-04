#!/usr/bin/env python3
"""Print total_secrets_found from a js_findings.json file."""
import json, sys
try:
    d = json.load(open(sys.argv[1]))
    print(d.get("scan_summary", {}).get("total_secrets_found", 0))
except Exception:
    print(0)
