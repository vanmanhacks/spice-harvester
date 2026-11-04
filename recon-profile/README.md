# Recon Profile

The Spice Harvester AI layer runs on a dedicated Hermes profile (a "Bot"): a
named agent with its own model, memory, and skills, isolated under
`~/.hermes/profiles/recon/`. Routing suggestion + synthesis through this profile
gives the pipeline a *second* persistence layer beyond `target_knowledge.json`:
the agent writes what it learns into its own memory, so each scan makes the next
sharper.

## What it does

| Task | Skill | Output |
| --- | --- | --- |
| Suggest candidate subdomains/endpoints | `recon-suggestion` | JSON `{subdomains}` / `{endpoints}` |
| Synthesize the final report | `recon-synthesis` | `final_report.md` + memory update |

The pipeline calls it headless (the prompt is self-contained; the skills in
`skills/` document the methodology and may be auto-loaded by the agent):

```bash
hermes -p recon chat --query-file - --oneshot -Q --max-turns 3 --run-budget 90
```

Every invocation falls back to a direct DeepSeek API call (`ai_suggest.py` /
`synthesis_gate.py`) if the agent is unavailable or produces no usable output,
so the pipeline never breaks.

## Setup (any machine)

```bash
# from the repo root
./recon-profile/setup.sh recon <your-DEEPSEEK-API-key>
```

This:

1. Creates the `recon` profile (`hermes profile create`).
2. Pins the model to `deepseek-flash` (low temperature for deterministic JSON).
3. Deploys the two skills.
4. Writes the API key to the profile's `.env` (a profile does **not** inherit the
   default profile's `~/.hermes/.env` key — it must be set explicitly).

Then enable it in the pipeline environment:

```bash
# .env (or /etc/spice-harvester/env)
AI_ENABLED=1
```

## Requirements

- Hermes installed and on `PATH`
  (`curl -fsSL https://hermes-agent.nousresearch.com/install.sh | bash`).
- A DeepSeek API key (global `~/.hermes/.env`, or profile `.env`).

## Data egress

Enabling `AI_ENABLED` sends discovered scan data (subdomain names, URLs,
technology fingerprints) to `api.deepseek.com`, a third-party inference
provider. Keep this in mind for engagements under NDA. With `AI_ENABLED`
unset, the only DeepSeek traffic is the direct-API synthesis gate
(`synthesis_gate.py`).

## Memory isolation

The recon profile's memory is **per-profile and cumulative** — every scan's
learnings persist and are injected into the next run. That is the
self-improvement loop, but it also means a profile shared across engagements
leaks client A's infrastructure into client B's report.

For clean separation, use **one profile per engagement**:

```bash
./recon-profile/setup.sh recon-acme       # creates ~/.hermes/profiles/recon-acme
# in the pipeline env for that engagement:
RECON_PROFILE=recon-acme
```

Each profile has its own memory, skills, and sessions. The default `recon` is
fine for a single engagement; never reuse it across clients.

## Reproducibility

The *setup* is reproducible and self-contained: the skills are version-controlled
in `recon-profile/skills/`, and `setup.sh` is idempotent. To carry the profile —
including its accumulated memory — to another machine, use
`hermes profile export recon` / `hermes profile import`.

The AI *output*, however, is heuristic, not byte-reproducible: an agent with
persistent memory and a non-deterministic model means two runs can diverge.
The deterministic baseline is `AI_ENABLED` **off** — permutation + direct-API
synthesis at temperature 0 — which is what open-source users should treat as
the reproducible mode.
