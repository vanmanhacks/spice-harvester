#!/usr/bin/env python3
"""rank_targets.py — Score live hosts by offensive interest from httpx JSON.

Reads live_hosts.json (one httpx JSON object per line) from stdin.
Scores each host on 5 signals (0–12 total), outputs ranked URLs to stdout.
"""

import json
import re
import sys
from collections import Counter

# ── Scoring constants ──────────────────────────────────────────────────────

HOSTNAME_PATTERNS = [
    (re.compile(r'(auth|oauth|sso|saml|login|signin)', re.I), 4),
    (re.compile(r'(api|graphql|rest|query)', re.I), 4),
    (re.compile(r'(admin|portal|dashboard|internal|gateway|bff)', re.I), 3),
    (re.compile(r'(dev|stage|staging|test|qa|sandbox|demo)', re.I), 2),
]

HOSTNAME_NEGATIVE = re.compile(r'(cdn|status|monitor|metrics|health|uptime)', re.I)

HIGH_TECH = {'graphql', 'swagger', 'express', 'rails', 'django', 'ruby on rails',
             'django rest framework', 'fastapi', 'flask', 'spring', 'spring boot',
             'laravel', 'symfony', 'asp.net', '.net', 'next.js', 'nuxt.js'}
MID_TECH = {'nginx', 'apache', 'tomcat', 'node.js', 'golang', 'python', 'php',
            'iis', 'caddy', 'traefik', 'envoy'}
CDN_TECH = {'cloudflare', 'akamai', 'cloudfront', 'fastly', 'cdn', 'cloudflare bot management'}

CDN_PROVIDERS = {'cloudflare', 'akamai', 'cloudfront', 'fastly'}

TITLE_INTERESTING = re.compile(r'(api|admin|dashboard|portal|graphql|swagger|docs|console)', re.I)
TITLE_ERROR = re.compile(r'(503|502|access denied|not found|forbidden|error|unavailable)', re.I)


def hostname_score(url: str) -> int:
    """Score based on subdomain/hostname patterns."""
    best = 0
    for pattern, score in HOSTNAME_PATTERNS:
        if pattern.search(url):
            best = max(best, score)
    if HOSTNAME_NEGATIVE.search(url) and best == 0:
        return 0
    return best


def tech_score(tech_list: list[str]) -> int:
    """Score based on technology stack."""
    if not tech_list:
        return 0
    tech_lower = {t.lower().strip() for t in tech_list}
    if tech_lower & HIGH_TECH:
        return 3
    if tech_lower & MID_TECH:
        return 2
    if tech_lower - CDN_TECH:  # has any non-CDN tech
        return 1
    return 0


def status_score(code: int) -> int:
    """Score based on HTTP status code."""
    if code in (200, 401, 403):
        return 2
    if code in (301, 302, 307, 308):
        return 1
    return 0


def title_score(title: str) -> int:
    """Score based on page title."""
    if not title:
        return 0
    if TITLE_INTERESTING.search(title):
        return 2
    if TITLE_ERROR.search(title):
        return 0
    # Has a title that isn't an error page
    if len(title.strip()) > 3:
        return 1
    return 0


def non_waf_bonus(host: dict) -> int:
    """Bonus point for hosts not behind a blocking WAF."""
    cdn = (host.get('cdn_name') or '').lower()
    title = host.get('title') or ''
    if cdn in CDN_PROVIDERS and TITLE_ERROR.search(title):
        return 0  # definitely blocked
    if cdn in CDN_PROVIDERS:
        return 0  # behind CDN, assume blocked
    return 1


# ── Main ────────────────────────────────────────────────────────────────────

def main():
    hosts = []
    scores = Counter()

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

        s_host = hostname_score(url)
        s_tech = tech_score(h.get('tech') or [])
        s_stat = status_score(h.get('status_code', 0))
        s_title = title_score(h.get('title') or '')
        s_waf = non_waf_bonus(h)

        total = s_host + s_tech + s_stat + s_title + s_waf
        if total < 1:
            total = 1  # any live host is at least minimally interesting

        scores[total] += 1
        hosts.append((total, url))

    hosts.sort(key=lambda x: x[0], reverse=True)

    for score, url in hosts:
        print(url)

    # Debug output to stderr
    total = len(hosts)
    print(f"[*] Ranked {total} targets by offensive interest", file=sys.stderr)
    print(f"[*] Score distribution: {dict(sorted(scores.items(), reverse=True))}", file=sys.stderr)
    if total > 0:
        top_score = hosts[0][0]
        top_count = sum(1 for s, _ in hosts if s == top_score)
        print(f"[*] Top score: {top_score} ({top_count} hosts)", file=sys.stderr)
        print(f"[*] Median score: {hosts[total // 2][0]}", file=sys.stderr)


if __name__ == '__main__':
    main()
