#!/usr/bin/env python3
"""scan_status.py — Aggregate per-domain scan progress into one JSON file.

Reads every pipeline/output/<domain>/monthly/ directory, merges each
status.json heartbeat (phase / tool / elapsed_s / bytes / last_growth_s) with
artifact line counts, and writes pipeline/output/scan_status.json. Read-only:
never modifies scan state. Run on demand (dashboard poll, cron, or a human).

Usage:
  python3 pipeline/scripts/scan_status.py
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

SPICE_HOME = Path(
    os.environ.get("SPICE_HARVESTER_HOME", Path(__file__).resolve().parent.parent.parent)
)
OUTPUT_DIR = SPICE_HOME / "pipeline" / "output"


def line_count(path: Path) -> int:
    try:
        return sum(1 for _ in path.open())
    except OSError:
        return 0


def load_status(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError):
        return {}


def detect_mode(log_path: Path):
    """Last 'PIPELINE START (<mode>)' line in pipeline.log, or None."""
    try:
        lines = log_path.read_text().splitlines()
    except OSError:
        return None
    mode = None
    for line in lines:
        if "PIPELINE START" in line:
            if "(monthly)" in line:
                mode = "monthly"
            elif "(weekly)" in line:
                mode = "weekly"
    return mode


def main() -> None:
    domains = []
    for d in sorted(OUTPUT_DIR.glob("*/monthly")):
        domain = d.parent.name
        st = load_status(d / "status.json")
        report = d / "final_report.md"
        domains.append({
            "domain": domain,
            "done": report.is_file() and report.stat().st_size > 0,
            "phase": st.get("phase", ""),
            "tool": st.get("tool", ""),
            "elapsed_s": st.get("elapsed_s", 0),
            "bytes": st.get("bytes", 0),
            "last_growth_s": st.get("last_growth_s", 0),
            "counts": {
                "subs": line_count(d / "all_subdomains.txt"),
                "live": line_count(d / "live_subdomains.txt"),
                "urls": line_count(d / "all_urls.txt"),
            },
        })

    result = {
        "mode": detect_mode(OUTPUT_DIR / "pipeline.log"),
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "domains": domains,
    }

    out = OUTPUT_DIR / "scan_status.json"
    out.write_text(json.dumps(result, indent=2) + "\n")
    done = sum(1 for x in domains if x["done"])
    in_progress = sum(1 for x in domains if x["phase"] and not x["done"])
    print(out)
    print(f"[*] {len(domains)} domain(s): {done} done, {in_progress} in progress", file=sys.stderr)


if __name__ == "__main__":
    main()
