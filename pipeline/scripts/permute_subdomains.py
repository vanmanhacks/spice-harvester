#!/usr/bin/env python3
"""
Spice Harvester — Deterministic Subdomain Permutation Engine
Replaces suggest_subdomains.py's LLM call with pure pattern-based permutation.

Extracts naming conventions from existing subdomains and generates candidate
subdomains by combining detected environments, regions, services, and
infrastructure patterns. No API call — runs in <1s.

Usage:
  python3 permute_subdomains.py <domain> <live_subdomains_file> <output_file>
"""
import re
import sys
from collections import Counter


def extract_patterns(subdomains: list[str], domain: str) -> dict:
    """Extract naming patterns from existing subdomains."""
    prefixes = Counter()
    suffixes = Counter()
    word_parts = Counter()
    environments = set()
    regions = set()
    services = set()

    env_pattern = re.compile(
        r'\b(dev|stage|staging|prod|prd|uat|test|qa|sandbox|demo|preprod|dr|canary)\b',
        re.IGNORECASE,
    )
    region_pattern = re.compile(r'\b(us[eaw]|eu|ap|na|sa|af|me)\w*\d*\b', re.IGNORECASE)

    for sub in subdomains:
        name = sub.replace(f".{domain}", "")
        parts = name.split(".")

        for part in parts:
            if not part:
                continue
            if len(part) >= 3:
                prefixes[part[:4]] += 1
            if len(part) >= 3:
                suffixes[part[-3:]] += 1

            segments = re.split(r'[-_]|\d+', part)
            for seg in segments:
                if len(seg) >= 3:
                    word_parts[seg.lower()] += 1

            env_match = env_pattern.search(part)
            if env_match:
                environments.add(env_match.group(1).lower())

            reg_match = region_pattern.search(part)
            if reg_match:
                regions.add(reg_match.group(1).lower())

            for svc in [
                'api', 'auth', 'cdn', 'admin', 'portal', 'gateway', 'bff',
                'graphql', 'ws', 'rest', 'vpn', 'mail', 'smtp', 'dns', 'ftp',
                'monitor', 'metrics', 'health', 'status', 'docs', 'wiki',
                'jenkins', 'git', 'registry', 'artifactory', 'nexus',
                'kibana', 'grafana', 'prometheus', 'alertmanager',
                'kafka', 'rabbitmq', 'redis', 'mongo', 'postgres', 'mysql',
                's3', 'storage', 'assets', 'static', 'media', 'images',
                'app', 'm', 'mobile', 'web', 'www', 'internal',
            ]:
                if svc == part.lower() or part.lower().startswith(svc):
                    services.add(svc)

    return {
        "top_prefixes": [p for p, _ in prefixes.most_common(10)],
        "top_suffixes": [s for s, _ in suffixes.most_common(10)],
        "top_words": [w for w, _ in word_parts.most_common(15)],
        "environments": sorted(environments),
        "regions": sorted(regions),
        "services": sorted(services),
        "subdomain_count": len(subdomains),
        "sample_subdomains": subdomains[:30] if len(subdomains) > 30 else subdomains,
    }


def generate_permutations(domain: str, patterns: dict) -> set[str]:
    """Generate candidate subdomains purely from pattern combinations."""
    suggestions = set()

    envs = patterns.get("environments", [])
    regions = patterns.get("regions", [])
    services = patterns.get("services", [])
    words = patterns.get("top_words", [])

    # Defaults when detection produces nothing
    if not envs:
        envs = ["dev", "stage", "prod", "test", "sandbox", "uat"]
    if not services:
        services = ["api", "auth", "admin", "cdn", "portal", "gateway", "monitoring"]
    if not regions:
        regions = ["us-east-1", "us-west-2", "eu-west-1", "ap-southeast-1"]

    # Environment × service permutations
    for env in list(envs)[:6]:
        for svc in list(services)[:10]:
            suggestions.add(f"{env}-{svc}.{domain}")
            suggestions.add(f"{svc}-{env}.{domain}")
            suggestions.add(f"{env}{svc}.{domain}")

    # Regional permutations
    for region in list(regions)[:5]:
        for svc in list(services)[:6]:
            suggestions.add(f"{svc}.{region}.{domain}")

    # Word × service combinations
    for word in list(words)[:10]:
        for svc in list(services)[:5]:
            if word not in svc and svc not in word:
                suggestions.add(f"{word}-{svc}.{domain}")
                suggestions.add(f"{svc}-{word}.{domain}")

    # Internal/infrastructure subdomains
    infra = [
        "jenkins", "gitlab", "grafana", "kibana", "prometheus", "alertmanager",
        "vault", "consul", "registry", "artifactory", "nexus", "sonarqube",
        "k8s", "kubernetes", "rancher", "traefik", "nginx", "haproxy",
        "build", "ci", "cd", "deploy", "logs", "splunk", "elastic",
        "puppet", "ansible", "chef", "salt", "terraform",
    ]
    for name in infra:
        suggestions.add(f"{name}.{domain}")
        for env in list(envs)[:4]:
            suggestions.add(f"{name}-{env}.{domain}")

    # Numeric suffix permutations on top 5 service names
    for svc in list(services)[:5]:
        for n in range(1, 6):
            suggestions.add(f"{svc}{n:02d}.{domain}")
            suggestions.add(f"{svc}-{n:02d}.{domain}")

    # Prefix/suffix combinations from detected patterns
    prefixes = patterns.get("top_prefixes", [])[:6]
    suffixes = patterns.get("top_suffixes", [])[:6]
    for pfx in prefixes:
        for sfx in suffixes:
            if pfx != sfx:
                suggestions.add(f"{pfx}{sfx}.{domain}")

    return suggestions


def main():
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <domain> <live_subdomains_file> <output_file>",
              file=sys.stderr)
        sys.exit(1)

    domain = sys.argv[1]
    subdomains_file = sys.argv[2]
    output_file = sys.argv[3]

    try:
        with open(subdomains_file) as f:
            subdomains = [line.strip().lower() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[-] File not found: {subdomains_file}", file=sys.stderr)
        sys.exit(1)

    if not subdomains:
        print("[-] No subdomains to analyze", file=sys.stderr)
        sys.exit(0)

    print(f"[*] Extracting patterns from {len(subdomains)} subdomains...", file=sys.stderr)
    patterns = extract_patterns(subdomains, domain)

    print(f"[*] Generating permutations...", file=sys.stderr)
    suggestions = generate_permutations(domain, patterns)

    with open(output_file, "w") as f:
        for sub in sorted(suggestions):
            f.write(f"{sub}\n")

    print(f"[*] Generated {len(suggestions)} candidate subdomains → {output_file}", file=sys.stderr)


if __name__ == "__main__":
    main()
