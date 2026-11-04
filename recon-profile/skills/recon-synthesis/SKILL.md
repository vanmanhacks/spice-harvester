---
name: recon-synthesis
category: recon
description: Synthesize recon scan output into a prioritized report, recalling past scans from memory and persisting what changed.
tags: [recon, synthesis, report, spice-harvester]
---

# Recon Synthesis

Turn a scan's aggregated output into a prioritized, actionable report.

## Input
- Scan summary (subdomain/host/URL counts, tech stacks, vulnerability-pattern matches).
- Past productive patterns + prior targets (from memory and/or target_knowledge.json).

## Method
1. Recall past scans of this target from memory — note what changed (new hosts,
   new tech, new patterns).
2. Produce three sections:
   - **Attack Surface Assessment** — top 5–10 vectors, specific hosts/endpoints/tech.
   - **Finding Prioritization** — which pattern matches are most likely real, not false positives.
   - **Target Profile & Next Steps** — highest-priority hosts, recommended manual testing.
3. If vulnerability scanning was skipped (all hosts behind one WAF/CDN), say so
   explicitly and recommend alternatives (API fuzzing, auth testing, takeover
   checks against non-WAF hosts).

## Rules
- Be specific: reference actual hostnames, endpoints, and technologies.
- Never fabricate vulnerabilities. If data is insufficient, say so.
- Keep the report under 500 lines.
- Your FINAL message must be the complete report body — no preamble, no
  "report saved" summary, no trailing commentary.

## Memory
After the report, persist new patterns, changed assets, and key findings to
memory. This is the self-improvement loop — each scan makes the next sharper.
