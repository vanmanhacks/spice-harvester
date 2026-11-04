#!/usr/bin/env python3
"""
Spice Harvester — Deterministic Endpoint Permutation Engine
Replaces suggest_endpoints.py's LLM call with pure pattern-based permutation.

Analyzes discovered URLs, tech stacks, and naming conventions to generate
candidate endpoints without any API call. Runs in <1s.

Usage:
  python3 permute_endpoints.py <domain> <all_urls_file> <tech_summary_file> <output_file>
"""
import os
import re
import sys
from collections import Counter


def extract_patterns(urls: list[str], tech_stacks: list[str]) -> dict:
    """Extract URL path patterns and technology context."""
    path_segments = Counter()
    api_versions = set()
    file_extensions = Counter()
    naming_conventions = set()
    environments = set()
    services = set()

    env_pattern = re.compile(
        r'/(dev|stage|staging|prod|prd|uat|test|qa|sandbox|demo|preprod|dr|canary)/',
        re.IGNORECASE,
    )
    svc_pattern = re.compile(
        r'/(api|auth|admin|portal|gateway|bff|graphql|rest|ws|cdn|assets|static|upload|download|export|import|config|health|status|metrics|monitor)/',
        re.IGNORECASE,
    )

    for url in urls:
        match = re.search(r'https?://[^/]+(/.*)', url)
        if not match:
            continue
        path = match.group(1)
        segments = [s for s in path.split('/') if s and len(s) < 64]

        for seg in segments:
            path_segments[seg] += 1

            if seg in ('v1', 'v2', 'v3', 'v4', 'v5', 'latest'):
                api_versions.add(seg)

            ext = os.path.splitext(seg)[1]
            if ext:
                file_extensions[ext] += 1

            if '-' in seg:
                naming_conventions.add('kebab-case')
            if '_' in seg:
                naming_conventions.add('snake_case')

            env_match = env_pattern.search(f'/{seg}/')
            if env_match:
                environments.add(env_match.group(1).lower())

            svc_match = svc_pattern.search(f'/{seg}') if not seg.isdigit() else None
            if svc_match:
                services.add(svc_match.group(1).lower())

    return {
        "top_path_segments": [p for p, _ in path_segments.most_common(30)],
        "api_versions": sorted(api_versions),
        "file_extensions": [e for e, _ in file_extensions.most_common(10)],
        "naming_conventions": sorted(naming_conventions),
        "environments": sorted(environments),
        "services": sorted(services),
        "technologies": tech_stacks[:15],
        "url_count": len(urls),
    }


def generate_endpoints(domain: str, patterns: dict) -> set[str]:
    """Generate candidate endpoints purely from pattern combinations."""
    endpoints = set()

    envs = patterns.get("environments", [])
    services = patterns.get("services", [])
    tech = " ".join(patterns.get("technologies", []))
    api_versions = patterns.get("api_versions", [])

    if not envs:
        envs = ["dev", "stage", "prod", "test"]
    if not services:
        services = ["api", "auth", "admin", "portal", "gateway"]

    # Framework-specific endpoints based on detected tech
    tech_lower = tech.lower()
    framework_paths = []
    if "django" in tech_lower or "python" in tech_lower:
        framework_paths = ["/admin", "/admin/login", "/api/v1/", "/api-auth/"]
    if "nginx" in tech_lower:
        framework_paths += ["/nginx_status", "/server-status"]
    if "apache" in tech_lower:
        framework_paths += ["/server-info", "/server-status", "/cgi-bin/"]
    if "tomcat" in tech_lower:
        framework_paths += ["/manager/html", "/host-manager/html", "/examples/"]
    if "grafana" in tech_lower:
        framework_paths += ["/api/health", "/api/dashboards/home", "/login"]
    if "kibana" in tech_lower:
        framework_paths += ["/api/status", "/app/kibana"]
    if "jenkins" in tech_lower:
        framework_paths += ["/script", "/computer/", "/api/json", "/job/"]
    if "gitlab" in tech_lower:
        framework_paths += ["/api/v4/", "/explore", "/users/sign_in", "/-/graphql-explorer"]
    if "wordpress" in tech_lower or "wp" in tech_lower:
        framework_paths += ["/wp-admin", "/wp-login.php", "/wp-json/wp/v2/"]
    if "ruby" in tech_lower or "rails" in tech_lower:
        framework_paths += ["/rails/info", "/rails/mailers", "/sidekiq"]
    if "php" in tech_lower:
        framework_paths += ["/phpinfo.php", "/info.php", "/.php"]
    if "node" in tech_lower or "express" in tech_lower:
        framework_paths += ["/health", "/metrics", "/.env"]

    # Always include these
    standard = [
        "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
        "/.git/config", "/.env", "/backup", "/console", "/debug",
        "/phpinfo.php", "/info.php",
        "/actuator", "/actuator/health", "/swagger-ui.html",
        "/api-docs", "/openapi.json", "/graphql",
        "/.well-known/openid-configuration",
        "/crossdomain.xml", "/clientaccesspolicy.xml",
        "/server-status", "/status",
    ]

    all_base = framework_paths + standard
    for path in all_base:
        endpoints.add(f"https://{domain}{path}")

    # Environment × service permutations
    for env in list(envs)[:5]:
        for svc in list(services)[:8]:
            endpoints.add(f"https://{domain}/{env}/{svc}")
            endpoints.add(f"https://{domain}/{svc}/{env}")
            endpoints.add(f"https://{domain}/api/{env}/{svc}")

    # API version permutations
    all_versions = set(api_versions) | {"v1", "v2", "v3", "v4", "latest"}
    for ver in sorted(all_versions)[:6]:
        endpoints.add(f"https://{domain}/api/{ver}/")
        for svc in list(services)[:5]:
            endpoints.add(f"https://{domain}/api/{ver}/{svc}")

    # Auth permutations
    for env in list(envs)[:4]:
        for auth_path in ["login", "register", "signup", "sso", "oauth", "saml", "reset-password"]:
            endpoints.add(f"https://{domain}/{env}/{auth_path}")
            endpoints.add(f"https://{domain}/{auth_path}/{env}")

    # Admin/bootstrap paths
    admin_paths = [
        "/admin", "/administrator", "/panel", "/dashboard",
        "/manage", "/config", "/settings", "/setup",
        "/install", "/install.php", "/phpmyadmin",
        "/pma", "/mysql", "/db", "/database",
    ]
    for path in admin_paths:
        endpoints.add(f"https://{domain}{path}")
        for env in list(envs)[:3]:
            endpoints.add(f"https://{domain}/{env}{path}")

    # GraphQL variants
    graphql_paths = ["/graphql", "/gql", "/graphiql", "/query", "/playground"]
    for path in graphql_paths:
        endpoints.add(f"https://{domain}{path}")
        for env in list(envs)[:3]:
            endpoints.add(f"https://{domain}/{env}{path}")

    return endpoints


def main():
    if len(sys.argv) != 5:
        print(
            f"Usage: {sys.argv[0]} <domain> <all_urls_file> <tech_summary_file> <output_file>",
            file=sys.stderr,
        )
        sys.exit(1)

    domain = sys.argv[1]
    urls_file = sys.argv[2]
    tech_file = sys.argv[3]
    output_file = sys.argv[4]

    try:
        with open(urls_file) as f:
            urls = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"[-] URLs file not found: {urls_file}", file=sys.stderr)
        sys.exit(1)

    if not urls:
        print("[-] No URLs to analyze", file=sys.stderr)
        sys.exit(0)

    tech_stacks = []
    try:
        with open(tech_file) as f:
            for line in f:
                match = re.match(r'\s*\d+\s+(.*)', line)
                if match:
                    tech_stacks.append(match.group(1).strip())
    except FileNotFoundError:
        pass

    print(f"[*] Extracting patterns from {len(urls)} URLs...", file=sys.stderr)
    patterns = extract_patterns(urls, tech_stacks)

    print(f"[*] Generating endpoint permutations...", file=sys.stderr)
    endpoints = generate_endpoints(domain, patterns)

    with open(output_file, "w") as f:
        for ep in sorted(endpoints):
            f.write(f"{ep}\n")

    print(
        f"[*] Generated {len(endpoints)} candidate endpoints → {output_file}",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
