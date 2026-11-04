#!/usr/bin/env python3
"""Parse crt.sh JSON output into deduplicated subdomain list."""
import json, sys

domain = sys.argv[1] if len(sys.argv) > 1 else ""
data = json.load(sys.stdin)
names = set()
for entry in data:
    for name in entry.get("name_value", "").split(chr(10)):
        name = name.strip().lower()
        if domain and name.endswith(domain) and "*" not in name:
            names.add(name)
for n in sorted(names):
    print(n)
