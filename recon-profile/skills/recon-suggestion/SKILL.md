---
name: recon-suggestion
category: recon
description: Suggest candidate subdomains and endpoints for recon, grounded in discovered data and memory of productive patterns.
tags: [recon, subdomain, endpoint, suggestion, spice-harvester]
---

# Recon Suggestion

Generate additional candidate subdomains or endpoints for a recon target.

## Input
- Discovered live subdomains (or URLs) — ground every suggestion in what already exists.
- Detected technology stacks — key endpoint suggestions to the real tech.

## Method
1. Extract naming patterns from the input: prefixes, suffixes, environments
   (dev/stage/prod/uat/test/qa), regions (us-east/eu/ap/…), services
   (api/auth/cdn/admin/…), and numeric suffixes.
2. Cross-reference memory: recall productive patterns and naming conventions
   learned from past scans of this or similar targets.
3. Propose candidates that follow the observed conventions and common
   infrastructure names.

## Output format
Respond with JSON only — no prose, no markdown fences, no commentary:
- Subdomains: `{"subdomains": ["api.dev.example.com", …]}`
- Endpoints:  `{"endpoints": ["https://host/admin", …]}`

## Rules
- Only valid DNS names (subdomains) or full URLs (endpoints).
- Suggestions are hypotheses to be verified, not findings. Never present them as discovered.
- Cap at 100 candidates.

## Memory
After responding, persist newly observed naming patterns and productive
combinations to memory so they compound across runs.
