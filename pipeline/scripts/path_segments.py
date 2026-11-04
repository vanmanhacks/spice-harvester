#!/usr/bin/env python3
"""Extract path segments from URLs for wordlist generation."""
import re, sys, os

segments = set()
try:
    for line in sys.stdin:
        m = re.search(r'https?://[^/]+(/[^?#]*)', line.strip())
        if m:
            for seg in m.group(1).split('/'):
                seg = seg.strip().lower()
                if seg and len(seg) > 2 and not seg[0].isdigit():
                    segments.add(seg)
except Exception:
    pass

for s in sorted(segments):
    print(s)
