#!/usr/bin/env python3
"""
synthesis_aggregator.py — Collect all Spice Harvester pipeline output into unified JSON
for AI Synthesis Gate extrapolation of undiscovered assets.

Gathers: subdomains, live hosts, tech stacks, page titles, auth endpoints,
discovered URLs, parameters, JS findings, API schemas, gf pattern matches.

Output: synthesis_input.json — comprehensive target profile for LLM analysis.
"""

import json
import re
import sys
from pathlib import Path
from collections import defaultdict


def safe_load_json(filepath: Path) -> dict | list | None:
    """Load JSON, return None on failure."""
    try:
        with open(filepath) as f:
            return json.load(f)
    except Exception:
        return None


def safe_load_lines(filepath: Path) -> list[str]:
    """Load non-empty lines from a text file."""
    try:
        with open(filepath) as f:
            return [line.strip() for line in f if line.strip()]
    except Exception:
        return []


def safe_load_json_lines(filepath: Path) -> list[dict]:
    """Load newline-delimited JSON (httpx, nuclei, feroxbuster output)."""
    items = []
    try:
        with open(filepath) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        items.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    except Exception:
        pass
    return items


def extract_subdomains(run_dir: Path) -> dict:
    """Extract subdomain intelligence from Stage 1 + Gate 0 output."""
    result = {
        "live_subdomains": [],
        "subdomain_count": 0,
        "intel_annotated": False,
        "role_distribution": {},
    }

    subs = safe_load_lines(run_dir / "live_subdomains.txt")
    result["live_subdomains"] = subs[:500]  # Cap for LLM context
    result["subdomain_count"] = len(subs)

    # Check for Gate 0 intel
    intel = safe_load_json(run_dir / "subdomain_intel.json")
    if intel:
        result["intel_annotated"] = True
        roles = defaultdict(int)
        for entry in intel.get("annotated_subdomains", intel.get("subdomains", [])):
            role = entry.get("role", entry.get("classification", "unknown"))
            roles[role] += 1
        result["role_distribution"] = dict(roles)

    return result


def extract_hosts(run_dir: Path) -> dict:
    """Extract live host profiling from Stage 2 output."""
    result = {
        "live_urls": [],
        "host_count": 0,
        "tech_stacks": defaultdict(int),
        "titles": [],
        "servers": [],
    }

    hosts = safe_load_json_lines(run_dir / "live_hosts.json")
    result["host_count"] = len(hosts)

    for host in hosts[:100]:  # Cap for LLM context
        url = host.get("url", host.get("host", ""))
        if url:
            result["live_urls"].append(url)

        tech = host.get("tech", host.get("technology", []))
        if isinstance(tech, list):
            for t in tech:
                result["tech_stacks"][t] += 1
        elif isinstance(tech, str):
            result["tech_stacks"][tech] += 1

        title = host.get("title", "")
        if title:
            result["titles"].append(title)

        server = host.get("server", "")
        if server:
            result["servers"].append(server)

    result["tech_stacks"] = dict(
        sorted(result["tech_stacks"].items(), key=lambda x: x[1], reverse=True)[:30]
    )
    result["top_titles"] = result["titles"][:50]
    result["top_servers"] = list(set(result["servers"]))[:20]
    del result["titles"]
    del result["servers"]

    return result


def extract_endpoints(run_dir: Path) -> dict:
    """Extract discovered URLs/endpoints from Stage 3 output."""
    result = {
        "katana_urls": 0,
        "feroxbuster_endpoints": 0,
        "total_unique_urls": 0,
        "url_samples": [],
        "endpoint_patterns": defaultdict(int),
    }

    katana = safe_load_lines(run_dir / "katana_urls.txt")
    all_urls = safe_load_lines(run_dir / "all_urls.txt")

    result["katana_urls"] = len(katana)
    result["total_unique_urls"] = len(all_urls)
    # Stratified sample: pick up to 5 URLs per unique subdomain to give the LLM
    # diverse context across the target's surface, not just 100 alphabetically-adjacent URLs.
    by_host = {}
    for url in all_urls:
        match = re.match(r"(https?://[^/]+)", url)
        if match:
            host = match.group(1)
            if host not in by_host:
                by_host[host] = []
            if len(by_host[host]) < 5:
                by_host[host].append(url)
    url_samples = []
    for host_urls in by_host.values():
        url_samples.extend(host_urls)
    result["url_samples"] = url_samples[:150]  # ~30 hosts × 5 URLs each

    # Extract endpoint patterns (path segments before query params)
    for url in all_urls:
        match = re.search(r"https?://[^/]+(/[^?#]*)", url)
        if match:
            path = match.group(1)
            segments = [s for s in path.split("/") if s and not s[0].isdigit()]
            for seg in segments[:3]:
                result["endpoint_patterns"][seg] += 1

    result["endpoint_patterns"] = dict(
        sorted(result["endpoint_patterns"].items(), key=lambda x: x[1], reverse=True)[:50]
    )

    # Feroxbuster results
    ferox = safe_load_json_lines(run_dir / "ferox_results.json")
    result["feroxbuster_endpoints"] = len(ferox)

    return result


def extract_parameters(run_dir: Path) -> dict:
    """Extract discovered parameters from Stage 3 x8 output."""
    result = {"parameters_found": 0, "parameter_names": [], "parameter_samples": []}

    x8_results = safe_load_json(run_dir / "x8_results.json")
    if isinstance(x8_results, list):
        params_seen = set()
        for entry in x8_results:
            if isinstance(entry, dict):
                for param in entry.get("parameters", entry.get("params", [])):
                    if isinstance(param, str):
                        params_seen.add(param)
                    elif isinstance(param, dict):
                        name = param.get("name", param.get("parameter", ""))
                        if name:
                            params_seen.add(name)
        result["parameters_found"] = len(params_seen)
        result["parameter_names"] = sorted(params_seen)[:100]
        if x8_results:
            result["parameter_samples"] = x8_results[:10]

    return result


def extract_js_findings(run_dir: Path) -> dict:
    """Extract JS analysis findings from Stage 4 output."""
    js_data = safe_load_json(run_dir / "js_findings.json")
    if not js_data:
        return {"analyzed": False}

    summary = js_data.get("scan_summary", {})
    findings = js_data.get("findings", [])

    # Collect unique endpoint patterns from JS
    js_endpoints = set()
    js_secrets = []
    for f in findings[:50]:
        for ep in f.get("endpoints", []):
            js_endpoints.add(ep.get("type", ""))
        for secret in f.get("secrets", []):
            js_secrets.append(secret.get("type", ""))
        for hl in f.get("hakluke", []):
            js_endpoints.add(f"hakluke:{hl.get('type', '')}")

    return {
        "analyzed": True,
        "files_scanned": summary.get("total_files_scanned", 0),
        "files_with_findings": summary.get("files_with_findings", 0),
        "total_secrets": summary.get("total_secrets_found", 0),
        "total_endpoints": summary.get("total_endpoints_found", 0),
        "hakluke_patterns": summary.get("total_hakluke_patterns", 0),
        "endpoint_types_found": sorted(js_endpoints),
        "secret_types_found": sorted(set(js_secrets)),
    }


def extract_gf_matches(run_dir: Path) -> dict:
    """Extract vulnerability pattern matches from Stage 3 gf output."""
    gf_summary = safe_load_json(run_dir / "gf_summary.json")
    if not gf_summary:
        return {"filtered": False}

    return {
        "filtered": True,
        "total_matches": gf_summary.get("total_matches", 0),
        "patterns": {
            p: data.get("count", 0)
            for p, data in gf_summary.get("patterns", {}).items()
        },
    }


def main():
    if len(sys.argv) < 2:
        print("Usage: synthesis_aggregator.py <pipeline_run_dir>", file=sys.stderr)
        sys.exit(1)

    run_dir = Path(sys.argv[1])
    if not run_dir.is_dir():
        print(f"[-] Run directory not found: {run_dir}", file=sys.stderr)
        sys.exit(1)

    output = {
        "pipeline_run": run_dir.name,
        "subdomains": extract_subdomains(run_dir),
        "hosts": extract_hosts(run_dir),
        "endpoints": extract_endpoints(run_dir),
        "parameters": extract_parameters(run_dir),
        "js_findings": extract_js_findings(run_dir),
        "vulnerability_patterns": extract_gf_matches(run_dir),
    }

    # Add summary stats
    output["summary"] = {
        "total_subdomains": output["subdomains"]["subdomain_count"],
        "total_live_hosts": output["hosts"]["host_count"],
        "total_urls_discovered": output["endpoints"]["total_unique_urls"],
        "parameters_discovered": output["parameters"]["parameters_found"],
        "js_files_scanned": output["js_findings"].get("files_scanned", 0),
        "vulnerability_matches": output["vulnerability_patterns"].get("total_matches", 0),
    }

    outfile = run_dir / "synthesis_input.json"
    with open(outfile, "w") as f:
        json.dump(output, f, indent=2)

    print(f"[+] Synthesis input written: {outfile}")
    print(f"    Subdomains: {output['summary']['total_subdomains']}")
    print(f"    Live hosts: {output['summary']['total_live_hosts']}")
    print(f"    URLs: {output['summary']['total_urls_discovered']}")
    print(f"    Parameters: {output['summary']['parameters_discovered']}")
    print(f"    JS files: {output['summary']['js_files_scanned']}")
    print(f"    Vuln patterns: {output['summary']['vulnerability_matches']}")


if __name__ == "__main__":
    main()
