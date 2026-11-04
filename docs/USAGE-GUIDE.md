# Spice Harvester — Usage Guide

**GHOLA** (**G**hola **H**osts **O**bservation & **L**ateral **A**ssessment).

## One Document to Rule Them All

All deployment, configuration, and operational documentation has been consolidated into:

**→ `docs/IMPLEMENTATION-GUIDE.md`**

That is the single source of truth. Follow it in phase order — every step from bare metal to first engagement is covered.

## Quick Reference

| Need | Command |
|:-----|:--------|
| Health check | `hermes -s om-health-check chat -q "Run health check"` |
| Weekly light pipeline (manual) | `sudo systemctl start spice-harvester-weekly-light` |
| Monthly deep pipeline (manual) | `sudo systemctl start spice-harvester-monthly-deep` |
| View pipeline output | `ls ~/ghola/pipeline/output/tesla/weekly/` |
| Hermes recon profile | `hermes --profile recon` |
| Manual pipeline run | `bash pipeline/monthly-deep.sh` |

## Pipeline Tiers

| Tier | Timer | Schedule | Runtime |
|:-----|:------|:---------|:--------|
| Weekly Light | `spice-harvester-weekly-light` | Sunday 08:00 UTC | ~2h |
| Monthly Deep | `spice-harvester-monthly-deep` | 1st Sunday 02:00 UTC | ~12-18h |

## Skills

| Skill | Purpose |
|:------|:--------|
| `spice-harvester-orchestrator` | Synthesis gate — reads all pipeline output, produces attack plan |
| `spice-harvester-recon` | Pipeline analysis and exploitation decisions (2-tier: weekly-light + monthly-deep, includes OPSEC) |
| `om-health-check` | 6-service health probe (Searxng, Crawl4ai, Redis, Langfuse, Postgres, LiteLLM) |
