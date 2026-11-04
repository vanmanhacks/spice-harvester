#!/usr/bin/env python3
"""
Spice Harvester — Synthesis Gate (v3: Direct DeepSeek API)
Replaces the 100-line bash inline prompt + hermes chat -q with a direct
DeepSeek API call via urllib. No hermes agent overhead, no signal handler
inheritance, no env -i workarounds. Works identically from bash, cron,
systemd, or TUI.

Reads synthesis_input.json + target_knowledge.json → DeepSeek API →
writes final_report.md + updates target_knowledge.json.

Usage:
  python3 synthesis_gate.py <monthly_output_dir> <domain>
  DEEPSEEK_API_KEY must be in environment.
"""
import json
import os
import sys
import time
import urllib.request
import urllib.error
from pathlib import Path

DEEPSEEK_API_URL = "https://api.deepseek.com/v1/chat/completions"
MODEL = "deepseek-flash"
MAX_TOKENS = 4096
TIMEOUT = 300


def load_json(path: Path) -> dict | list | None:
    """Load JSON, return None on failure."""
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


def load_text(path: Path) -> str:
    """Load text file, return empty string on failure."""
    try:
        with open(path) as f:
            return f.read()
    except Exception:
        return ""


def build_prompt(
    run_dir: Path,
    domain: str,
    synthesis: dict,
    knowledge: dict | None,
) -> str:
    """Build a focused prompt for the DeepSeek API — not a kitchen sink."""
    summary = synthesis.get("summary", {})
    subs = synthesis.get("subdomains", {})
    hosts = synthesis.get("hosts", {})
    vuln = synthesis.get("vulnerability_patterns", {})

    live_count = summary.get("total_live_hosts", 0)
    subs_count = summary.get("total_subdomains", 0)
    urls_count = summary.get("total_urls_discovered", 0)
    vuln_matches = summary.get("vulnerability_matches", 0)

    # Key tech stacks
    tech_stacks = hosts.get("tech_stacks", {})
    top_tech = ", ".join(list(tech_stacks.keys())[:10])

    # Vulnerability pattern breakdown
    patterns = vuln.get("patterns", {})
    pattern_summary = ", ".join(
        f"{k}:{v}" for k, v in sorted(patterns.items(), key=lambda x: -x[1])[:8]
    )

    # Past knowledge context
    knowledge_context = ""
    if knowledge:
        past_targets = knowledge.get("past_targets", [])
        past_patterns = knowledge.get("productive_patterns", [])
        if past_patterns:
            knowledge_context = f"""
**Past Productive Patterns** (from previous scans):
{chr(10).join(f'- {p}' for p in past_patterns[-20:])}
"""
        if past_targets:
            knowledge_context += f"""
**Previous Targets Scanned:** {', '.join(past_targets[-10:])}
"""

    return f"""You are a senior penetration tester reviewing reconnaissance output for {domain}.

**Scan Summary:**
- Subdomains discovered: {subs_count}
- Live hosts: {live_count}
- URLs crawled: {urls_count:,}
- Vulnerability pattern matches: {vuln_matches}
- Top technologies: {top_tech}
- Pattern breakdown: {pattern_summary}
{knowledge_context}
**Your Task — Focus on these 3 things only:**

1. **Attack Surface Assessment** — What are the top 5-10 attack vectors based on tech stack,
   exposed services, and naming conventions? Be specific: which hosts, which endpoints,
   which technology versions.

2. **Finding Prioritization** — Of the {vuln_matches} pattern matches, which are most likely
   to be real vulnerabilities (not false positives)? Consider: tech stack relevance, endpoint
   sensitivity, and exploitability. If no vulnerability scan was performed (WAF-enveloped),
   state that explicitly.

3. **Target Profile & Recommendations** — Based on this scan, what should we focus on next?
   Which subdomains are highest priority? What manual testing would you do?

**Rules:**
- Be SPECIFIC. Reference actual hostnames, endpoints, and technologies from the scan.
- Do NOT fabricate vulnerabilities. If data is insufficient, say so.
- If the target is WAF-enveloped (all hosts behind Akamai/Cloudflare), note that nuclei
  scanning was skipped and recommend alternative approaches (API fuzzing, auth testing,
  subdomain takeover checks against non-WAF targets).
- Keep output under 500 lines. Focus on actionable findings.

Output only your analysis and recommendations — no code blocks, no file paths, no tool commands."""


def call_deepseek(prompt: str, api_key: str) -> str:
    """Call DeepSeek API directly via urllib. No hermes agent needed."""
    payload = json.dumps({
        "model": MODEL,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a senior penetration tester. Be specific and evidence-based. "
                    "Reference actual hostnames, URLs, and technologies. Do not fabricate "
                    "vulnerabilities. Prioritize actionable findings over generic advice."
                ),
            },
            {"role": "user", "content": prompt},
        ],
        "max_tokens": MAX_TOKENS,
        "temperature": 0.3,
    }).encode("utf-8")

    req = urllib.request.Request(
        DEEPSEEK_API_URL,
        data=payload,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )

    max_retries = 3
    backoff = [2, 4, 8]
    for attempt in range(max_retries + 1):
        try:
            with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
                body = json.loads(resp.read().decode("utf-8"))
                return body["choices"][0]["message"]["content"]
        except urllib.error.HTTPError as e:
            error_body = e.read().decode("utf-8", errors="replace")
            print(f"[-] DeepSeek API HTTP {e.code}: {error_body[:500]}", file=sys.stderr)
            if (e.code == 429 or e.code >= 500) and attempt < max_retries:
                delay = backoff[attempt]
                print(
                    f"[*] Retrying in {delay}s (attempt {attempt + 1}/{max_retries})...",
                    file=sys.stderr,
                )
                time.sleep(delay)
                continue
            return ""
        except Exception as e:
            print(f"[-] DeepSeek API call failed: {e}", file=sys.stderr)
            if attempt < max_retries:
                delay = backoff[attempt]
                print(
                    f"[*] Retrying in {delay}s (attempt {attempt + 1}/{max_retries})...",
                    file=sys.stderr,
                )
                time.sleep(delay)
                continue
            return ""
    return ""


def update_knowledge(
    knowledge_path: Path,
    domain: str,
    synthesis: dict,
) -> None:
    """Update target_knowledge.json with productive patterns from this scan."""
    knowledge = load_json(knowledge_path) or {
        "version": 1,
        "past_targets": [],
        "productive_patterns": [],
        "last_updated": None,
    }

    # Track this target
    targets = set(knowledge.get("past_targets", []))
    targets.add(domain)
    knowledge["past_targets"] = sorted(targets)

    # Extract productive patterns from tech stacks
    hosts = synthesis.get("hosts", {})
    tech_stacks = hosts.get("tech_stacks", {})
    new_patterns = set(knowledge.get("productive_patterns", []))

    for tech, count in tech_stacks.items():
        if count >= 3:
            new_patterns.add(f"tech:{tech}")

    # Extract productive endpoint segments
    endpoints = synthesis.get("endpoints", {})
    ep_patterns = endpoints.get("endpoint_patterns", {})
    for seg, count in ep_patterns.items():
        if count >= 5 and len(seg) >= 3:
            new_patterns.add(f"path:{seg}")

    knowledge["productive_patterns"] = sorted(new_patterns)[-50:]
    knowledge["last_updated"] = time.strftime("%Y-%m-%dT%H:%M:%SZ")

    try:
        with open(knowledge_path, "w") as f:
            json.dump(knowledge, f, indent=2)
    except Exception as e:
        print(f"[-] Failed to update target knowledge: {e}", file=sys.stderr)


def main():
    if len(sys.argv) != 3:
        print(
            f"Usage: {sys.argv[0]} <monthly_output_dir> <domain>",
            file=sys.stderr,
        )
        sys.exit(1)

    run_dir = Path(sys.argv[1])
    domain = sys.argv[2]

    api_key = os.environ.get("DEEPSEEK_API_KEY", "")
    if not api_key:
        print("[-] DEEPSEEK_API_KEY not set in environment", file=sys.stderr)
        sys.exit(1)

    # Load synthesis input
    synthesis = load_json(run_dir / "synthesis_input.json")
    if not synthesis:
        print("[-] synthesis_input.json not found or invalid", file=sys.stderr)
        sys.exit(1)

    # Load past knowledge
    # run_dir is .../pipeline/output/<domain>/monthly
    # Go up 4 levels to reach the repo root
    knowledge_dir = Path(os.environ.get(
        "SPICE_HARVESTER_HOME",
        str(run_dir.parent.parent.parent.parent),
    ))
    knowledge_path = knowledge_dir / "target_knowledge.json"
    knowledge = load_json(knowledge_path)

    # Build prompt
    print(f"[*] Building synthesis prompt for {domain}...", file=sys.stderr)
    prompt = build_prompt(run_dir, domain, synthesis, knowledge)

    # Call DeepSeek
    print(f"[*] Calling DeepSeek API ({MODEL})...", file=sys.stderr)
    start = time.time()
    report = call_deepseek(prompt, api_key)
    elapsed = time.time() - start
    print(f"[*] API call completed in {elapsed:.1f}s", file=sys.stderr)

    # Write report
    report_path = run_dir / "final_report.md"
    if report:
        with open(report_path, "w") as f:
            f.write(f"# Spice Harvester Synthesis Report — {domain}\n\n")
            f.write(f"**Generated:** {time.strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
            f.write(f"**Model:** {MODEL}\n")
            f.write(f"**API latency:** {elapsed:.1f}s\n\n")
            f.write(report)
        lines = report.count("\n") + 1
        print(f"[+] final_report.md written ({lines} lines)", file=sys.stderr)
    else:
        # Write stub report on failure
        summary = synthesis.get("summary", {})
        with open(report_path, "w") as f:
            f.write(f"# Spice Harvester Synthesis Report — {domain}\n\n")
            f.write("**GATE FAILED.** The DeepSeek API did not return a valid response.\n\n")
            f.write("## Raw Pipeline Statistics\n")
            f.write(f"- Subdomains: {summary.get('total_subdomains', '?')} discovered\n")
            f.write(f"- Live hosts: {summary.get('total_live_hosts', '?')}\n")
            f.write(f"- URLs: {summary.get('total_urls_discovered', 0):,}\n")
            f.write(f"- Vuln patterns: {summary.get('vulnerability_matches', '?')}\n")
        print("[!] Gate failed — stub report written", file=sys.stderr)

    # Update target knowledge
    update_knowledge(knowledge_path, domain, synthesis)
    print("[+] Target knowledge updated", file=sys.stderr)


if __name__ == "__main__":
    main()
