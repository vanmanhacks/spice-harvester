#!/usr/bin/env python3
"""dedup_hosts.py — Collapse CDN-fronted host aliases to one backend representative.

Reads live_hosts.json (one httpx JSON object per line) from stdin.
Groups hosts by a conservative backend fingerprint (title + status + webserver +
content_type + tech + final cname/A) so distinct apps are never merged, keeps
the representative with the shortest hostname per unique backend, and outputs
those URLs to stdout. Summary goes to stderr.
"""

import json
import sys


def hostname_of(url: str) -> str:
    """Strip scheme and any path/port, returning just the hostname."""
    host = url.split('://', 1)[-1] if '://' in url else url
    host = host.split('/', 1)[0]
    host = host.split('?', 1)[0]
    host = host.split('#', 1)[0]
    if ':' in host:
        host = host.split(':', 1)[0]
    return host


def backend_identity(h: dict) -> tuple:
    """Conservative backend fingerprint for a single httpx host object."""
    cname = h.get('cname')
    if cname:
        backend = str(cname[-1]).strip().rstrip('.')
    else:
        a = h.get('a')
        backend = ','.join(sorted(a)) if a else ''
    return (
        h.get('status_code', 0),
        h.get('title') or '',
        h.get('webserver') or '',
        h.get('content_type') or '',
        tuple(sorted(h.get('tech') or [])),
        backend,
    )


# ── Main ────────────────────────────────────────────────────────────────────

def main():
    hosts = 0
    groups = {}

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            h = json.loads(line)
        except json.JSONDecodeError:
            continue

        url = h.get('url') or h.get('host') or h.get('input', '')
        if not url:
            continue

        hosts += 1
        key = backend_identity(h)
        host = hostname_of(url)

        if key not in groups:
            groups[key] = (len(host), url)
        else:
            cur_len, _ = groups[key]
            if len(host) < cur_len:
                groups[key] = (len(host), url)

    for _, url in groups.values():
        print(url)

    # Debug output to stderr
    print(f"[*] Parsed {hosts} hosts", file=sys.stderr)
    print(f"[*] Collapsed to {len(groups)} unique backend groups", file=sys.stderr)


if __name__ == '__main__':
    main()
