#!/usr/bin/env python3
"""
Spice Harvester — Hermes recon profile wrapper.

Routes the AI layer (suggestion + synthesis) through a dedicated Hermes
'recon' profile so learning persists in the profile's memory across runs.
Falls back to the direct-API scripts (ai_suggest.py / synthesis_gate.py)
when hermes is unavailable or fails, so the pipeline never breaks.

Usage:
  python3 hermes_recon.py suggest-subdomains <domain> <live_subs> <out_file>
  python3 hermes_recon.py suggest-endpoints  <domain> <urls> <tech> <out_file>
  python3 hermes_recon.py synthesize <run_dir> <domain>

The recon profile is created by recon-profile/setup.sh. The AI layer is only
invoked when the pipeline runs with AI_ENABLED=1; see pipeline/run.py.
"""
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ai_suggest

PROFILE = os.environ.get("RECON_PROFILE", "recon")
SUGGEST_BUDGET = int(os.environ.get("RECON_SUGGEST_BUDGET", "90"))
SYNTH_BUDGET = int(os.environ.get("RECON_SYNTH_BUDGET", "400"))


def _strip_session_id(text: str) -> str:
    """Strip a trailing 'session_id: ...' line that hermes -Q may append."""
    lines = text.splitlines()
    while lines and (not lines[-1].strip() or lines[-1].strip().startswith("session_id:")):
        lines.pop()
    return "\n".join(lines).strip()


_ERROR_MARKERS = (
    "no usable credentials", "i can't help", "i cannot help", "i can not help",
    "as an ai", "i'm sorry", "i am sorry", "i apologize",
    "memory updated", "report saved", "report written",
)


def _plausible_report(text: str) -> bool:
    """A synthesis must be a real report, not a refusal / error / short stub."""
    t = (text or "").strip()
    if len(t) < 200:
        return False
    low = t.lower()
    return not any(low.startswith(m) for m in _ERROR_MARKERS)


def call_hermes(prompt: str, run_budget: int, max_turns: int) -> str:
    """Invoke the recon profile one-shot via stdin; return the response text ('' on failure).

    A non-empty response is returned even when hermes exits non-zero: the agent can
    emit a complete answer yet still exit 1 (run-budget / turn limits). Only an empty
    response counts as failure, which is what triggers the direct-API fallback.

    Truncation note: `--format stream-json` (which exposes finish_reason for
    truncation detection) is rejected by the gateway when combined with
    `--run-budget`, so it isn't used here. Truncated/implausible synthesis is
    instead caught by _plausible_report (min length + error markers).
    """
    cmd = [
        "hermes", "-p", PROFILE, "chat",
        "--query-file", "-", "--oneshot", "-Q",
        "--max-turns", str(max_turns),
        "--run-budget", str(run_budget),
        "--source", "tool",
        "--in", os.environ.get("RECON_SCRATCH_DIR", os.environ.get("TMPDIR", "/tmp")),
    ]
    try:
        r = subprocess.run(cmd, input=prompt, capture_output=True, text=True,
                           timeout=run_budget + 30)
        out = _strip_session_id(r.stdout or "")
        if out:
            return out
        if r.returncode != 0:
            err = (r.stderr or "").strip().splitlines()
            print(f"[-] hermes recon exited {r.returncode}: {err[-1] if err else 'no stderr'}",
                  file=sys.stderr)
        return ""
    except Exception as e:
        print(f"[-] hermes recon invocation failed: {e}", file=sys.stderr)
        return ""


def suggest_subdomains(domain: str, live_subs_file: str, out_file: str) -> int:
    """Suggestion via the recon profile; fall back to direct API."""
    ctx = ai_suggest._read_lines(live_subs_file)
    prompt = ai_suggest.build_prompt("subdomains", domain, ctx, [])
    text = call_hermes(prompt, SUGGEST_BUDGET, 3)
    cands = ai_suggest.filter_candidates(
        ai_suggest.parse_candidates(text, "subdomains"), domain, "subdomains"
    ) if text else []
    if not cands:
        print("[!] hermes suggest failed (or no in-scope candidates) — falling back to ai_suggest.py",
              file=sys.stderr)
        return ai_suggest.suggest("subdomains", domain, out_file, live_subs_file)
    Path(out_file).write_text("\n".join(cands) + ("\n" if cands else ""))
    print(f"[+] hermes suggest: {len(cands)} subdomain candidates -> {out_file}", file=sys.stderr)
    return 0


def suggest_endpoints(domain: str, urls_file: str, tech_file: str, out_file: str) -> int:
    """Endpoint suggestion via the recon profile; fall back to direct API."""
    ctx = ai_suggest._read_lines(urls_file)
    tech = ai_suggest._read_lines(tech_file) if tech_file and Path(tech_file).is_file() else []
    prompt = ai_suggest.build_prompt("endpoints", domain, ctx, tech)
    text = call_hermes(prompt, SUGGEST_BUDGET, 3)
    cands = ai_suggest.filter_candidates(
        ai_suggest.parse_candidates(text, "endpoints"), domain, "endpoints"
    ) if text else []
    if not cands:
        print("[!] hermes suggest failed (or no in-scope candidates) — falling back to ai_suggest.py",
              file=sys.stderr)
        return ai_suggest.suggest("endpoints", domain, out_file, urls_file, tech_file)
    Path(out_file).write_text("\n".join(cands) + ("\n" if cands else ""))
    print(f"[+] hermes suggest: {len(cands)} endpoint candidates -> {out_file}", file=sys.stderr)
    return 0


def synthesize(run_dir: str, domain: str) -> int:
    """Synthesis via the recon profile; fall back to direct API (synthesis_gate.py)."""
    import synthesis_gate  # lazy: the suggestion subcommands don't need this module

    d = Path(run_dir)
    synthesis = synthesis_gate.load_json(d / "synthesis_input.json")
    if not isinstance(synthesis, dict):
        print("[-] synthesis_input.json not found or invalid", file=sys.stderr)
        return 1

    knowledge_dir = Path(
        os.environ.get("SPICE_HARVESTER_HOME", str(d.parent.parent.parent.parent))
    ).expanduser()
    knowledge_path = knowledge_dir / "target_knowledge.json"
    knowledge = synthesis_gate.load_json(knowledge_path)
    if not isinstance(knowledge, dict):
        knowledge = None

    prompt = synthesis_gate.build_prompt(d, domain, synthesis, knowledge)
    prompt += (
        "\n\nUse the memory tool to persist new patterns and findings, THEN produce "
        "the complete report as your FINAL message. The report must be your final "
        "output — no 'memory updated' summary, no preamble, no commentary."
    )

    print(f"[*] Recon profile synthesis ({PROFILE})...", file=sys.stderr)
    start = time.time()
    text = call_hermes(prompt, SYNTH_BUDGET, 12)
    elapsed = time.time() - start

    if not _plausible_report(text):
        print("[!] hermes synthesize returned implausible output — falling back to synthesis_gate.py",
              file=sys.stderr)
        try:
            return subprocess.run(
                [sys.executable, str(Path(__file__).parent / "synthesis_gate.py"),
                 str(d), domain],
                timeout=SYNTH_BUDGET + 60,
            ).returncode
        except subprocess.TimeoutExpired:
            print("[-] synthesis_gate.py fallback timed out", file=sys.stderr)
            return 1

    report_path = d / "final_report.md"
    report_path.write_text(
        f"# Spice Harvester Synthesis Report — {domain}\n\n"
        f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
        f"**Model:** hermes recon profile ({PROFILE})\n"
        f"**Latency:** {elapsed:.1f}s\n\n"
        + text
    )
    print(f"[+] final_report.md written ({text.count(chr(10)) + 1} lines)", file=sys.stderr)

    synthesis_gate.update_knowledge(knowledge_path, domain, synthesis)
    print("[+] target knowledge updated", file=sys.stderr)
    return 0


def main() -> None:
    argv = sys.argv[1:]
    if argv and argv[0] == "suggest-subdomains" and len(argv) == 4:
        sys.exit(suggest_subdomains(argv[1], argv[2], argv[3]))
    if argv and argv[0] == "suggest-endpoints" and len(argv) == 5:
        sys.exit(suggest_endpoints(argv[1], argv[2], argv[3], argv[4]))
    if argv and argv[0] == "synthesize" and len(argv) == 3:
        sys.exit(synthesize(argv[1], argv[2]))
    print(__doc__, file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
    main()
