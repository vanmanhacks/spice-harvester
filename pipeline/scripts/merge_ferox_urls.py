#!/usr/bin/env python3
"""Merge katana URLs and feroxbuster JSON output into a single deduplicated URL list for GF pattern matching."""
import json, sys

urls = set()
ferox_count = 0

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    if line.startswith('{'):
        try:
            url = json.loads(line).get('url', '')
            if url:
                urls.add(url)
                ferox_count += 1
        except (json.JSONDecodeError, KeyError):
            pass
    else:
        urls.add(line)

for url in sorted(urls):
    print(url)

print(f"[*] Merged: {len(urls)} unique URLs ({ferox_count} from feroxbuster)", file=sys.stderr)
