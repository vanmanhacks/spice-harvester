#!/usr/bin/env python3
"""
Spice Harvester pipeline — Python orchestrator.

Replaces monthly-deep.sh and weekly-light.sh (both archived). Fixes the bug classes
found in the 2026-11 review by construction:

  * Correct stdin passing (no `< /dev/null` swallowing host-side redirects).
  * Per-target `flock` serializes the weekly/monthly tiers.
  * Per-domain exception handling — one target failing never aborts the run.
  * Scope-domain validation prevents shell/path injection.
  * No `set -e` traps — every tool failure is handled explicitly.
  * Graceful Signal alerts (never abort the run).
  * One `detect_waf()` helper instead of three copy-pasted inline Python blocks.

Usage:
  python3 pipeline/run.py monthly [--force]
  python3 pipeline/run.py weekly
"""

import argparse
import fcntl
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# ── Config ────────────────────────────────────────────────────────────────
SPICE_HOME = Path(
    os.environ.get("SPICE_HARVESTER_HOME", Path(__file__).resolve().parent.parent)
)
OUTPUT_DIR = SPICE_HOME / "pipeline" / "output"
SCOPE_FILE = Path(os.environ.get("SCOPE_FILE", SPICE_HOME / "scope.txt"))
CONTAINER = "spice-harvester-recon-runner"
LOG_FILE = OUTPUT_DIR / "pipeline.log"

# Intensity knobs (was scattered bash vars)
KATANA_DEPTH = 3
FEROX_DEPTH = 3
JS_CAP = 100
HIGH_VALUE_CAP = 30
NUCLEI_TARGETED_TEMPLATES = (
    "/root/nuclei-templates/http/cves/ /root/nuclei-templates/http/exposed-panels/ "
    "/root/nuclei-templates/http/misconfiguration/ /root/nuclei-templates/http/default-logins/ "
    "/root/nuclei-templates/http/exposures/"
)
NUCLEI_BROAD_TEMPLATES = (
    "/root/nuclei-templates/http/cves/ /root/nuclei-templates/http/exposed-panels/ "
    "/root/nuclei-templates/http/misconfiguration/"
)
GF_PATTERNS = "xss sqli ssrf lfi redirect idor debug-pages upload-fields s3-buckets"
WAF_BYPASS_HEADERS = [
    "X-Forwarded-For: 127.0.0.1",
    "X-Real-IP: 127.0.0.1",
    "X-Forwarded-Host: {domain}",
    "X-Originating-IP: 127.0.0.1",
    "X-Remote-IP: 127.0.0.1",
    "X-Remote-Addr: 127.0.0.1",
]

# Low-and-slow HTTP rate limits (req/s) — WAF-evasion defaults, tune per
# engagement. ferox/nuclei/katana were already conservative; httpx was not.
HTTPX_RATE_LIMIT = os.environ.get("HTTPX_RATE_LIMIT", "20")
HTTPX_THREADS = os.environ.get("HTTPX_THREADS", "20")
FEROX_RATE_LIMIT = os.environ.get("FEROX_RATE_LIMIT", "10")
NUCLEI_RATE_LIMIT = os.environ.get("NUCLEI_RATE_LIMIT", "5")

# Generous tool timeouts (seconds) — hang-guards, not truncation targets. On
# timeout the pipeline keeps partial results and warns instead of failing.
SUBFINDER_TIMEOUT = int(os.environ.get("SUBFINDER_TIMEOUT", "7200"))
DNSX_TIMEOUT = int(os.environ.get("DNSX_TIMEOUT", "3600"))
HTTPX_TIMEOUT = int(os.environ.get("HTTPX_TIMEOUT", "7200"))
KATANA_TIMEOUT = int(os.environ.get("KATANA_TIMEOUT", "7200"))
FEROX_TIMEOUT = int(os.environ.get("FEROX_TIMEOUT", "14400"))
NUCLEI_TIMEOUT = int(os.environ.get("NUCLEI_TIMEOUT", "14400"))


# ── Helpers ────────────────────────────────────────────────────────────────
def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def log(msg: str) -> None:
    """Append a pipeline-log entry. Never raises."""
    try:
        LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with LOG_FILE.open("a") as f:
            f.write(f"[{now()}] {msg}\n")
    except Exception:
        pass


def alert(msg: str) -> None:
    """Send a Signal alert. Always returns (never aborts the run)."""
    acct = os.environ.get("SIGNAL_ACCOUNT", "")
    rcpt = os.environ.get("SIGNAL_RECIPIENT", "")
    if not acct or not rcpt:
        print(f"[-] alert skipped (SIGNAL_ACCOUNT/RECIPIENT unset): {msg[:60]}", file=sys.stderr)
        return
    try:
        subprocess.run(
            ["signal-cli", "--account", acct, "send", "-m", msg, rcpt],
            capture_output=True, timeout=30,
        )
    except Exception:
        pass  # alerting must never kill the pipeline


def ai_enabled() -> bool:
    """True when the AI layer (Hermes recon profile) is enabled via AI_ENABLED=1."""
    return os.environ.get("AI_ENABLED", "").strip().lower() in ("1", "true", "yes", "on")


def _run_tool(cmd: list[str], timeout: int, **kw) -> subprocess.CompletedProcess | None:
    """Run a tool with a generous timeout; on timeout keep partial output + warn.

    The caller typically passes stdout=<file>, so partial content survives a
    TimeoutExpired. We warn and return None so the phase continues instead of
    failing the whole domain.
    """
    try:
        return subprocess.run(cmd, timeout=timeout, **kw)
    except subprocess.TimeoutExpired:
        print(f"[!] {cmd[0]} timed out after {timeout}s — keeping partial results",
              file=sys.stderr)
        return None


def docker_exec(*args: str, stdin_text: str | None = None, timeout: int | None = None,
                capture: bool = False, _warn: bool = True) -> subprocess.CompletedProcess:
    """Run a command inside the recon container.

    stdin_text is passed through correctly (Python `input=`), fixing the old
    `< /dev/null` override that silently fed feroxbuster/wc empty stdin. When no
    stdin is given, an empty EOF is supplied so `docker exec -i` never hangs.
    """
    cmd = ["docker", "exec", "-i", CONTAINER, *args]
    r = subprocess.run(
        cmd, input=stdin_text if stdin_text is not None else "", text=True,
        capture_output=capture, timeout=timeout,
    )
    if _warn and r.returncode != 0:
        print(f"[!] command exited {r.returncode}: {args[0]}", file=sys.stderr)
    return r


def docker_exec_bash(script: str, **kw) -> subprocess.CompletedProcess:
    """Run a bash -c script inside the container (for multi-command pipelines)."""
    r = docker_exec("bash", "-c", script, _warn=False, **kw)
    if r.returncode != 0:
        print(f"[!] command exited {r.returncode}: bash -c", file=sys.stderr)
    return r


def host_python(script: str, *args: str, stdin_text: str | None = None) -> subprocess.CompletedProcess:
    """Run a host-side pipeline script (Python)."""
    r = subprocess.run(
        [sys.executable, str(SPICE_HOME / "pipeline" / "scripts" / script), *args],
        input=stdin_text, text=True, capture_output=True,
    )
    if r.returncode != 0:
        print(f"[!] command exited {r.returncode}: {script}", file=sys.stderr)
    return r


def line_count(path: Path) -> int:
    """Count lines in a host-side file. Never raises."""
    try:
        return sum(1 for _ in path.open())
    except Exception:
        return 0


def _merge_lines(dest: Path, *srcs: Path) -> int:
    """Merge unique non-empty lines from dest + srcs into dest (host-side). Returns count.

    dest's existing content is preserved implicitly; each line is stripped.
    """
    seen: set[str] = set()
    for src in (dest, *srcs):
        if src.is_file():
            seen.update(l.strip() for l in src.read_text().splitlines() if l.strip())
    lines = sorted(seen)
    dest.write_text("\n".join(lines) + ("\n" if lines else ""))
    return len(lines)


def _clear_artifacts(d: Path, names: list[str]) -> None:
    """Remove stale run-scoped artifacts so a tier never inherits another's output."""
    for name in names:
        p = d / name
        if p.is_file():
            p.unlink()


def detect_waf(live_hosts_json: Path) -> int:
    """Count hosts whose httpx output reports cdn_type == 'waf'."""
    waf = 0
    try:
        for line in live_hosts_json.open():
            line = line.strip()
            if not line:
                continue
            try:
                if json.loads(line).get("cdn_type") == "waf":
                    waf += 1
            except json.JSONDecodeError:
                pass
    except Exception:
        return 0
    return waf


def scope_domains() -> list[str]:
    """Parse scope.txt → unique root domains (strip *. wildcard, skip comments).

    Rejects anything that isn't a plain DNS name — prevents shell/path injection
    when the domain is interpolated into bash -c and output paths.
    """
    if not SCOPE_FILE.is_file():
        print(f"[-] No scope.txt at {SCOPE_FILE}", file=sys.stderr)
        sys.exit(1)
    valid = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9-]+)+$", re.IGNORECASE)
    domains = []
    for raw in SCOPE_FILE.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        domain = line.removeprefix("*.")
        if not valid.match(domain):
            print(f"[-] Invalid scope domain (skipped): {raw}", file=sys.stderr)
            continue
        domains.append(domain)
    return sorted(set(domains))


def _host_of(x: str) -> str:
    """Normalize a URL/host string to a bare hostname (for baseline diffs)."""
    x = x.strip()
    if "://" in x:
        x = x.split("://", 1)[1]
    return x.split("/", 1)[0].split(":", 1)[0]


def scope_exclusions() -> list[str]:
    """Extract out-of-scope hosts from comments like '# Out of scope: a.x, b.y'."""
    exclusions = []
    for raw in SCOPE_FILE.read_text().splitlines():
        if "out of scope" in raw.lower() or "out-of-scope" in raw.lower():
            rest = raw.split(":", 1)[-1]
            for tok in rest.replace(",", " ").split():
                tok = tok.split("/", 1)[0].strip()
                if tok:
                    exclusions.append(tok)
    return exclusions


def with_lock(target: Path, fn):
    """Run fn holding an exclusive lock on <target>.lock (serializes tiers)."""
    lock_path = target / ".lock"
    target.mkdir(parents=True, exist_ok=True)
    with lock_path.open("w") as lock_fh:
        for _ in range(60):
            try:
                fcntl.flock(lock_fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                time.sleep(5)
        else:
            print(f"[!] lock held too long, skipping: {lock_path}", file=sys.stderr)
            return
        try:
            return fn()
        finally:
            fcntl.flock(lock_fh, fcntl.LOCK_UN)


# ── Phases ─────────────────────────────────────────────────────────────────
def phase_discover(domain: str, d: Path, mode: str) -> dict:
    """Phase 1 — subdomain discovery (subfinder + crt.sh + dnsx + httpx + permute)."""
    print("[*] Phase 1: Discovery")

    # Weekly: snapshot the monthly baseline before discovery overwrites it
    if mode == "weekly" and (d / "all_subdomains.txt").is_file():
        (d / "baseline_prev.txt").write_bytes((d / "all_subdomains.txt").read_bytes())

    # Clear stale discovery artifacts (after the baseline snapshot above)
    _clear_artifacts(d, ["subfinder.txt", "crtsh.txt", "dnsx_brute.txt",
                         "resolved_subdomains.txt",
                         "live_hosts.json", "live_subdomains.txt",
                         "suggested_subs.txt", "suggested_subs_ai.txt",
                         "suggested_live.json", "suggested_live.txt", "tech_summary.txt"])

    # Kill stale dnsmasq (container may lack pkill)
    docker_exec_bash(
        'for p in /proc/[0-9]*; do [ -f "$p/comm" ] && [ "$(cat "$p/comm")" = dnsmasq ] '
        '&& kill "${p##*/}" 2>/dev/null; done'
    )
    time.sleep(1)
    subprocess.Popen(
        ["docker", "exec", "-i", CONTAINER, "dnsmasq", "-k"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )

    # crt.sh (direct; the commented proxychains fallback lives in the old script)
    crtsh_code = docker_exec_bash(
        f"curl -s --connect-timeout 30 --max-time 60 -o /tmp/crtsh.json "
        f"-w '%{{http_code}}' 'https://crt.sh/?q=%25.{domain}&output=json'",
        capture=True,
    ).stdout.strip()
    _run_tool(
        ["docker", "exec", "-i", CONTAINER, "subfinder", "-d", domain, "-silent"],
        SUBFINDER_TIMEOUT,
        stdout=(d / "subfinder.txt").open("w"), stderr=subprocess.DEVNULL,
    )
    (d / "root_domain.txt").write_text(domain + "\n")

    if crtsh_code == "200":
        subprocess.run(
            ["docker", "exec", "-i", CONTAINER, "bash", "-c",
             f"python3 /app/scripts/parse_crtsh.py '{domain}' < /tmp/crtsh.json"],
            stdout=(d / "crtsh.txt").open("w"), stderr=subprocess.DEVNULL,
        )
    else:
        (d / "crtsh.txt").touch()
        print(f"[!] crt.sh blocked (HTTP {crtsh_code})")

    # dnsx brute
    _run_tool(
        ["docker", "exec", "-i", CONTAINER, "dnsx", "-d", domain,
         "-w", "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt", "-silent"],
        DNSX_TIMEOUT,
        stdout=(d / "dnsx_brute.txt").open("w"), stderr=subprocess.DEVNULL,
    )

    # Merge + sanitize all subdomain sources: lowercase, drop cert-log noise
    # (wildcards, emails, leading dashes), dedupe.
    docker_exec_bash(
        f"cat /app/output/{domain}/monthly/subfinder.txt "
        f"/app/output/{domain}/monthly/crtsh.txt "
        f"/app/output/{domain}/monthly/dnsx_brute.txt 2>/dev/null "
        f"| tr '[:upper:]' '[:lower:]' | grep -vE '^[*@-]|@' | sort -u "
        f"> /app/output/{domain}/monthly/all_subdomains.txt"
    )
    subs = line_count(d / "all_subdomains.txt")

    # Kill dnsmasq
    docker_exec_bash(
        'for p in /proc/[0-9]*; do [ -f "$p/comm" ] && [ "$(cat "$p/comm")" = dnsmasq ] '
        '&& kill "${p##*/}" 2>/dev/null; done'
    )

    # Resolve candidates with dnsx first (fast concurrent DNS) so httpx only
    # probes hosts that actually resolve. Prevents junk-heavy domains (e.g.
    # example.com's ~43K cert-log entries) from drowning httpx.
    _run_tool(
        ["docker", "exec", "-i", CONTAINER, "dnsx",
         "-l", f"/app/output/{domain}/monthly/all_subdomains.txt", "-silent"],
        DNSX_TIMEOUT,
        stdout=(d / "resolved_subdomains.txt").open("w"), stderr=subprocess.DEVNULL,
    )

    # httpx liveness (tech-detect + CDN detection feed synthesis + WAF envelope)
    _run_tool(
        ["docker", "exec", "-i", CONTAINER, "httpx",
         "-list", f"/app/output/{domain}/monthly/resolved_subdomains.txt",
         "-td", "-cdn", "-t", HTTPX_THREADS, "-rl", HTTPX_RATE_LIMIT, "-silent", "-json",
         "-o", f"/app/output/{domain}/monthly/live_hosts.json"],
        HTTPX_TIMEOUT, stderr=subprocess.DEVNULL,
    )
    docker_exec_bash(
        f"cat /app/output/{domain}/monthly/live_hosts.json | "
        f"jq -r '.url // .host // empty' > /app/output/{domain}/monthly/live_subdomains.txt"
    )

    # Scope exclusion filter
    exclusions = scope_exclusions()
    if exclusions:
        live = d / "live_subdomains.txt"
        kept = [l for l in live.read_text().splitlines() if l and l not in exclusions]
        live.write_text("\n".join(kept) + ("\n" if kept else ""))

    live = line_count(d / "live_subdomains.txt")
    print(f"[*] Subdomains: {subs}, live: {live}")

    # Candidate generation: deterministic permutation + (AI_ENABLED) recon profile
    host_python("permute_subdomains.py", domain,
                str(d / "live_subdomains.txt"), str(d / "suggested_subs.txt"))
    if ai_enabled():
        host_python("hermes_recon.py", "suggest-subdomains", domain,
                    str(d / "live_subdomains.txt"), str(d / "suggested_subs_ai.txt"))
        _merge_lines(d / "suggested_subs.txt", d / "suggested_subs_ai.txt")
    suggested = line_count(d / "suggested_subs.txt")
    if suggested > 0:
        _run_tool(
            ["docker", "exec", "-i", CONTAINER, "httpx",
             "-list", f"/app/output/{domain}/monthly/suggested_subs.txt",
             "-t", HTTPX_THREADS, "-rl", HTTPX_RATE_LIMIT, "-silent", "-json",
             "-o", f"/app/output/{domain}/monthly/suggested_live.json"],
            HTTPX_TIMEOUT, stderr=subprocess.DEVNULL,
        )
        docker_exec_bash(
            f"cat /app/output/{domain}/monthly/suggested_live.json 2>/dev/null | "
            f"jq -r '.url // .host // empty' > /app/output/{domain}/monthly/suggested_live.txt"
        )
        if line_count(d / "suggested_live.txt") > 0:
            # Only CONFIRMED (httpx-verified live) suggestions enter the baseline.
            # Raw candidates (suggested_subs.txt) stay out until they resolve, so
            # model guesses never pollute the observed set or the weekly diff.
            docker_exec_bash(
                f"cat /app/output/{domain}/monthly/live_subdomains.txt "
                f"/app/output/{domain}/monthly/suggested_live.txt 2>/dev/null | sort -u "
                f"> /app/output/{domain}/monthly/live_subdomains.txt.tmp && "
                f"mv /app/output/{domain}/monthly/live_subdomains.txt.tmp "
                f"/app/output/{domain}/monthly/live_subdomains.txt"
            )
            docker_exec_bash(
                f"cat /app/output/{domain}/monthly/all_subdomains.txt "
                f"/app/output/{domain}/monthly/suggested_live.txt 2>/dev/null | sort -u "
                f"> /app/output/{domain}/monthly/all_subdomains.txt.tmp && "
                f"mv /app/output/{domain}/monthly/all_subdomains.txt.tmp "
                f"/app/output/{domain}/monthly/all_subdomains.txt"
            )
    live = line_count(d / "live_subdomains.txt")

    # Weekly: keep only hosts new since the previous baseline (compare hostnames)
    if mode == "weekly":
        known = set()
        if (d / "baseline_prev.txt").is_file():
            known = {_host_of(x) for x in (d / "baseline_prev.txt").read_text().splitlines() if x}
        new_hosts = [l for l in (d / "live_subdomains.txt").read_text().splitlines()
                     if l and _host_of(l) not in known]
        (d / "live_subdomains.txt").write_text("\n".join(new_hosts) + ("\n" if new_hosts else ""))
        (d / "new_hosts.txt").write_text("\n".join(new_hosts) + ("\n" if new_hosts else ""))
        live = len(new_hosts)
        print(f"[*] Weekly: {live} new hosts since baseline")

    # Tech summary (feeds endpoint permutation)
    tech = docker_exec_bash(
        f"cat /app/output/{domain}/monthly/live_hosts.json | "
        f"jq -r '(.tech // .technology // []) | join(\" \")' 2>/dev/null | "
        f"tr ' ' '\\n' | sort | uniq -c | sort -rn | head -20",
        capture=True,
    )
    (d / "tech_summary.txt").write_text(tech.stdout)

    return {"subs": subs, "live": live}


def phase_surface(domain: str, d: Path, mode: str) -> int:
    """Phase 2 — surface mapping (katana + gau [+ ferox on monthly] + permute + x8 + auth)."""
    print("[*] Phase 2: Surface Mapping")

    # Clear stale surface artifacts
    _clear_artifacts(d, ["katana_urls.txt", "gau_urls.txt", "all_urls.txt",
                         "all_urls_comprehensive.txt", "high_value_targets.txt",
                         "ferox_results.json", "ferox_results_full.json", "ferox_results_deep.json",
                         "ferox_urls_flat.txt", "suggested_endpoints.txt",
                         "suggested_endpoints_ai.txt", "endpoints_live.json",
                         "endpoints_live.txt",
                         "x8_results.json", "auth_endpoints.txt"])

    # katana crawl
    _run_tool(
        ["docker", "exec", "-i", CONTAINER, "katana",
         "-list", f"/app/output/{domain}/monthly/live_subdomains.txt",
         "-jc", "-d", str(KATANA_DEPTH), "-c", "5", "--delay", "2", "-silent",
         "-o", f"/app/output/{domain}/monthly/katana_urls.txt"],
        KATANA_TIMEOUT, stderr=subprocess.DEVNULL,
    )

    # gau (bounded)
    subprocess.run(
        ["docker", "exec", "-i", CONTAINER, "timeout", "300", "gau", "--subs", domain,
         "--providers", "wayback,otx", "--retries", "2",
         "-o", f"/app/output/{domain}/monthly/gau_urls.txt"],
        stderr=subprocess.DEVNULL,
    )

    # Merge
    docker_exec_bash(
        f"cat /app/output/{domain}/monthly/katana_urls.txt "
        f"/app/output/{domain}/monthly/gau_urls.txt 2>/dev/null | sort -u "
        f"> /app/output/{domain}/monthly/all_urls.txt"
    )
    urls = line_count(d / "all_urls.txt")

    # Rank high-value targets
    live_json = d / "live_hosts.json"
    if not live_json.is_file():
        live_json.write_text("")
    r = host_python("rank_targets.py", stdin_text=live_json.read_text())
    targets = r.stdout.splitlines()
    if not targets:
        targets = [l for l in (d / "live_subdomains.txt").read_text().splitlines() if l]
    targets = targets[:HIGH_VALUE_CAP]
    (d / "high_value_targets.txt").write_text("\n".join(targets) + ("\n" if targets else ""))
    hv = len(targets)

    # feroxbuster — monthly only (the ~10-16h part); stdin passed CORRECTLY
    if mode == "monthly":
        _run_tool(
            ["docker", "exec", "-i", CONTAINER, "feroxbuster", "--stdin",
             "--rate-limit", FEROX_RATE_LIMIT, "--random-agent", "--json", "-t", "10",
             "-w", "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
             "-n", "-o", f"/app/output/{domain}/monthly/ferox_results_full.json"],
            FEROX_TIMEOUT, input="\n".join(targets), text=True, stderr=subprocess.DEVNULL,
        )
        _run_tool(
            ["docker", "exec", "-i", CONTAINER, "feroxbuster", "--stdin",
             "--rate-limit", FEROX_RATE_LIMIT, "--random-agent", "--json", "-t", "10",
             "-w", "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt",
             "--depth", "2", "-o", f"/app/output/{domain}/monthly/ferox_results_deep.json"],
            FEROX_TIMEOUT, input="\n".join(targets[:10]), text=True, stderr=subprocess.DEVNULL,
        )

    # Comprehensive URL set (ferox contributes only on monthly)
    if mode == "monthly":
        docker_exec_bash(
            f"cat /app/output/{domain}/monthly/ferox_results_full.json "
            f"/app/output/{domain}/monthly/ferox_results_deep.json 2>/dev/null "
            f"> /app/output/{domain}/monthly/ferox_results.json"
        )
        docker_exec_bash(
            f"python3 /app/scripts/merge_ferox_urls.py "
            f"< /app/output/{domain}/monthly/ferox_results.json 2>/dev/null "
            f"> /app/output/{domain}/monthly/ferox_urls_flat.txt"
        )
        docker_exec_bash(
            f"cat /app/output/{domain}/monthly/katana_urls.txt "
            f"/app/output/{domain}/monthly/gau_urls.txt "
            f"/app/output/{domain}/monthly/ferox_urls_flat.txt 2>/dev/null | sort -u "
            f"> /app/output/{domain}/monthly/all_urls_comprehensive.txt"
        )
    else:
        docker_exec_bash(
            f"cat /app/output/{domain}/monthly/katana_urls.txt "
            f"/app/output/{domain}/monthly/gau_urls.txt 2>/dev/null | sort -u "
            f"> /app/output/{domain}/monthly/all_urls_comprehensive.txt"
        )

    # Endpoint permutation (deterministic) + (AI_ENABLED) recon profile
    host_python("permute_endpoints.py", domain,
                str(d / "all_urls_comprehensive.txt"),
                str(d / "tech_summary.txt") if (d / "tech_summary.txt").exists() else "/dev/null",
                str(d / "suggested_endpoints.txt"))
    if ai_enabled():
        host_python("hermes_recon.py", "suggest-endpoints", domain,
                    str(d / "all_urls_comprehensive.txt"),
                    str(d / "tech_summary.txt") if (d / "tech_summary.txt").exists() else "/dev/null",
                    str(d / "suggested_endpoints_ai.txt"))
        _merge_lines(d / "suggested_endpoints.txt", d / "suggested_endpoints_ai.txt")
    if line_count(d / "suggested_endpoints.txt") > 0:
        _run_tool(
            ["docker", "exec", "-i", CONTAINER, "httpx",
             "-list", f"/app/output/{domain}/monthly/suggested_endpoints.txt",
             "-t", HTTPX_THREADS, "-rl", HTTPX_RATE_LIMIT, "-silent", "-json",
             "-o", f"/app/output/{domain}/monthly/endpoints_live.json"],
            HTTPX_TIMEOUT, stderr=subprocess.DEVNULL,
        )
        docker_exec_bash(
            f"cat /app/output/{domain}/monthly/endpoints_live.json 2>/dev/null | "
            f"jq -r '.url // .host // empty' > /app/output/{domain}/monthly/endpoints_live.txt"
        )
        if line_count(d / "endpoints_live.txt") > 0:
            docker_exec_bash(
                f"cat /app/output/{domain}/monthly/all_urls_comprehensive.txt "
                f"/app/output/{domain}/monthly/endpoints_live.txt 2>/dev/null | sort -u "
                f"> /app/output/{domain}/monthly/all_urls.txt"
            )
        else:
            docker_exec_bash(
                f"cp /app/output/{domain}/monthly/all_urls_comprehensive.txt "
                f"/app/output/{domain}/monthly/all_urls.txt"
            )
    else:
        docker_exec_bash(
            f"cp /app/output/{domain}/monthly/all_urls_comprehensive.txt "
            f"/app/output/{domain}/monthly/all_urls.txt"
        )
    urls = line_count(d / "all_urls.txt")

    # x8 parameter discovery
    docker_exec_bash(
        f"unset HTTP_PROXY HTTPS_PROXY http_proxy https_proxy; "
        f"x8 -u /app/output/{domain}/monthly/live_subdomains.txt "
        f"-w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt "
        f"--delay 500 -O json -o /app/output/{domain}/monthly/x8_results.json"
    )

    # Auth probing
    auth = 0
    auth_script = (
        "AUTH_PATHS='signup register auth sso oauth2 saml reset-password dashboard admin panel'; "
        "while IFS= read -r url; do for path in $AUTH_PATHS; do "
        "code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "
        "-H 'X-Forwarded-For: 127.0.0.1' \"${url}/${path}\" 2>/dev/null || echo 000); "
        '[ "$code" != 404 ] && [ "$code" != 000 ] && echo \"${url}/${path} ${code}\"; '
        f"done; done < /app/output/{domain}/monthly/live_subdomains.txt"
    )
    r = docker_exec_bash(auth_script, capture=True)
    (d / "auth_endpoints.txt").write_text(r.stdout)
    auth = line_count(d / "auth_endpoints.txt")

    return urls


def phase_vuln(domain: str, d: Path, waf_enveloped: bool, mode: str) -> dict:
    """Phase 3 — vulnerability scan (nuclei + gf + JS + API), or WAF-skip stub."""
    if waf_enveloped:
        print("[*] Phase 3: SKIPPED — WAF envelope")
        for name in ("nuclei_targeted.json", "nuclei_broad.json", "nuclei_results.json",
                     "js_urls.txt", "api_candidates.txt"):
            (d / name).touch()
        (d / "gf_summary.json").write_text('{"total_matches":0,"patterns":{}}')
        (d / "js_findings.json").write_text(
            '{"scan_summary":{"total_files_scanned":0,"files_with_findings":0,'
            '"total_secrets_found":0},"findings":[]}'
        )
        return {"nuclei": 0, "gf": 0, "js": 0, "api": 0}

    # Clear stale per-run artifacts (weekly must not inherit monthly's broad scan)
    for name in ("nuclei_targeted.json", "nuclei_broad.json", "nuclei_results.json",
                 "js_urls.txt", "api_candidates.txt"):
        p = d / name
        if p.is_file():
            p.unlink()

    print("[*] Phase 3: Vulnerability Scan")
    if mode == "monthly":
        _run_tool(["docker", "exec", "-i", CONTAINER, "nuclei", "-update-templates", "-silent"],
                  NUCLEI_TIMEOUT, stderr=subprocess.DEVNULL)

    hdrs = [h.format(domain=domain) for h in WAF_BYPASS_HEADERS]
    header_args = []
    for h in hdrs:
        header_args += ["-H", h]
    nuclei_args = ["-rl", NUCLEI_RATE_LIMIT, "-bs", "2", "-c", "5", "-silent", "-jsonl"] + header_args

    # Pass 1: targeted (high-value, critical+high)
    _run_tool(
        ["docker", "exec", "-i", CONTAINER, "nuclei",
         "-list", f"/app/output/{domain}/monthly/high_value_targets.txt",
         "-t", *NUCLEI_TARGETED_TEMPLATES.split(), "-severity", "critical,high",
         *nuclei_args, "-o", f"/app/output/{domain}/monthly/nuclei_targeted.json"],
        NUCLEI_TIMEOUT, stderr=subprocess.DEVNULL,
    )
    (d / "nuclei_targeted.json").touch()

    # Pass 2: broad (all live, critical) — monthly only
    if mode == "monthly":
        _run_tool(
            ["docker", "exec", "-i", CONTAINER, "nuclei",
             "-list", f"/app/output/{domain}/monthly/live_subdomains.txt",
             "-t", *NUCLEI_BROAD_TEMPLATES.split(), "-severity", "critical",
             *nuclei_args, "-o", f"/app/output/{domain}/monthly/nuclei_broad.json"],
            NUCLEI_TIMEOUT, stderr=subprocess.DEVNULL,
        )
        (d / "nuclei_broad.json").touch()

    docker_exec_bash(
        f"cat /app/output/{domain}/monthly/nuclei_targeted.json "
        f"/app/output/{domain}/monthly/nuclei_broad.json 2>/dev/null | sort -u "
        f"> /app/output/{domain}/monthly/nuclei_results.json"
    )
    nuclei = line_count(d / "nuclei_results.json")

    # gf patterns
    for pattern in GF_PATTERNS.split():
        docker_exec_bash(
            f"cat /app/output/{domain}/monthly/all_urls.txt 2>/dev/null | "
            f"gf {pattern} 2>/dev/null > /app/output/{domain}/monthly/gf_{pattern}.txt"
        )
    docker_exec("python3", "/app/scripts/gf_summary.py", f"/app/output/{domain}/monthly")
    gf = 0
    try:
        gf = json.loads((d / "gf_summary.json").read_text()).get("total_matches", 0)
    except Exception:
        pass

    # JS secrets
    subprocess.run(
        ["docker", "exec", "-i", CONTAINER, "bash", "/app/scripts/download_js.sh",
         f"/app/output/{domain}/monthly/js_urls.txt", f"/app/output/{domain}/monthly/js_files/"],
        stderr=subprocess.DEVNULL, timeout=600,
    )
    subprocess.run(
        ["docker", "exec", "-i", CONTAINER, "python3", "/app/scripts/js_secrets.py",
         "--js-dir", f"/app/output/{domain}/monthly/js_files/",
         "--output", f"/app/output/{domain}/monthly/js_findings.json"],
        stderr=subprocess.DEVNULL, timeout=300,
    )
    js = 0
    try:
        jf = json.loads((d / "js_findings.json").read_text())
        js = jf.get("scan_summary", {}).get("total_secrets_found", 0)
    except Exception:
        pass

    # API probes
    api_script = (
        "while IFS= read -r url; do for path in /graphql /api /api/v1 /swagger "
        "/openapi.json /api-docs /v2 /v3 /graphiql /query; do "
        'code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "${url}${path}" '
        '2>/dev/null || echo 000); '
        '[ "$code" != 404 ] && [ "$code" != 000 ] && echo "${url}${path} ${code}"; '
        f"done; done < /app/output/{domain}/monthly/live_subdomains.txt"
    )
    r = docker_exec_bash(api_script, capture=True)
    (d / "api_candidates.txt").write_text(r.stdout)
    api = line_count(d / "api_candidates.txt")

    return {"nuclei": nuclei, "gf": gf, "js": js, "api": api}


def phase_synthesize(domain: str, d: Path) -> None:
    """Phase 4 — wordlist mining + synthesis (aggregator + recon profile / DeepSeek gate)."""
    print("[*] Phase 4: Synthesis + Wordlists")
    docker_exec_bash(
        f"cat /app/output/{domain}/monthly/all_subdomains.txt | tr '.' '\\n' | tr '-' '\\n' | "
        f"grep -E '^[a-zA-Z0-9]{{3,}}$' | sort -u "
        f"> /app/output/{domain}/monthly/wordlists/subdomain_keywords.txt"
    )
    docker_exec_bash(
        f"cat /app/output/{domain}/monthly/all_urls.txt | "
        f"python3 /app/scripts/path_segments.py "
        f"> /app/output/{domain}/monthly/wordlists/path_segments.txt"
    )
    docker_exec("python3", "/app/scripts/synthesis_aggregator.py", f"/app/output/{domain}/monthly")

    if ai_enabled():
        print("[*] Synthesis gate (Hermes recon profile)...")
        host_python("hermes_recon.py", "synthesize", str(d), domain)
    else:
        print("[*] Synthesis gate (DeepSeek)...")
        host_python("synthesis_gate.py", str(d), domain)
    if (d / "final_report.md").is_file() and (d / "final_report.md").stat().st_size > 0:
        print(f"[+] final_report.md ({line_count(d / 'final_report.md')} lines)")
    else:
        print("[!] synthesis gate produced no report")


# ── Orchestration ──────────────────────────────────────────────────────────
def run_domain(domain: str, mode: str, force: bool) -> None:
    target = domain  # full FQDN — avoids TLD collision
    d = OUTPUT_DIR / target / "monthly"
    d.mkdir(parents=True, exist_ok=True)
    (d / "wordlists").mkdir(exist_ok=True)
    (d / "js_files").mkdir(exist_ok=True)

    # Baseline: weekly requires a completed monthly; do not delete in place.
    baseline = d / "all_subdomains.txt"
    if mode == "weekly" and not baseline.is_file():
        print(f"[!] {target}: no monthly baseline — run monthly first; skipping")
        return

    def _run() -> None:
        start = time.time()
        print(f"\n{'=' * 55}\n  [{target}] mode={mode}\n{'=' * 55}")
        stats = phase_discover(domain, d, mode)

        if stats["live"] == 0:
            alert(f"[Spice Harvester {mode}] {target}: 0 live hosts; skipping")
            return

        waf = detect_waf(d / "live_hosts.json")
        waf_enveloped = (waf > 0 and waf >= stats["live"]) and not force

        urls = phase_surface(domain, d, mode)
        vuln = phase_vuln(domain, d, waf_enveloped, mode)
        phase_synthesize(domain, d)

        elapsed = time.time() - start
        alert(f"[Spice Harvester {mode}] {target} done in {elapsed:.0f}s — "
              f"{stats['subs']} subs / {stats['live']} live / {urls} URLs / "
              f"{vuln['nuclei']} nuclei / {vuln['js']} js")
        log(f"{mode.upper()} DONE — {target}: {stats['subs']} subs, {stats['live']} live, "
            f"{urls} URLs, {vuln['nuclei']} nuclei — {elapsed:.0f}s")

    with_lock(d, _run)


def main() -> None:
    ap = argparse.ArgumentParser(description="Spice Harvester pipeline")
    ap.add_argument("mode", choices=["monthly", "weekly"])
    ap.add_argument("--force", action="store_true",
                    help="scan through a detected WAF envelope anyway")
    args = ap.parse_args()

    domains = scope_domains()
    if not domains:
        print("[-] No valid domains in scope.txt", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Spice Harvester {args.mode} — {len(domains)} target(s)")
    log(f"PIPELINE START ({args.mode}) — {len(domains)} target(s)")

    failures = []
    for i, domain in enumerate(domains, 1):
        try:
            run_domain(domain, args.mode, args.force)
        except Exception as e:
            print(f"[-] {domain} FAILED: {e}", file=sys.stderr)
            log(f"FAIL {domain}: {e}")
            alert(f"[Spice Harvester {args.mode}] {domain} FAILED: {e}")
            failures.append(domain)

    if failures:
        print(f"[-] {len(failures)} domain(s) failed: {', '.join(failures)}")
    log(f"PIPELINE DONE ({args.mode}) — {len(domains) - len(failures)}/{len(domains)} domains")
    alert(f"[Spice Harvester {args.mode}] DONE — {len(domains) - len(failures)}/{len(domains)} domains")


if __name__ == "__main__":
    main()
