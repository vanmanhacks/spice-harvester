# Spice Harvester

*"The spice must flow."*

Autonomous, self-improving reconnaissance for bug bounty and offensive security. Spice Harvester runs automated subdomain discovery, surface mapping, vulnerability scanning, and AI-driven synthesis across a scope of targets on a two-tier schedule.

## Architecture

- **Orchestrator** — `pipeline/run.py`, a Python driver that replaces the earlier bash pipeline. Two tiers:
  - `monthly` — full deep scan (feroxbuster + broad nuclei), ~12–18h per domain
  - `weekly` — light scan (new hosts only, no feroxbuster), ~2h per domain
- **Tooling** — subfinder, dnsx, httpx, katana, gau, feroxbuster, x8, nuclei, gf — all run inside the `recon-runner` Docker container (`network_mode: host`).
- **AI layer (opt-in)** — a dedicated Hermes `recon` profile (agent-driven suggestion + synthesis with persistent, self-improving memory) via `hermes_recon.py`, falling back to the direct-API scripts (`ai_suggest.py` / `synthesis_gate.py`, `deepseek-flash` with retry/backoff) when the agent produces no usable output. Enable with `AI_ENABLED=1`; see `recon-profile/`.
- **Deterministic enrichment** — `permute_subdomains.py` and `permute_endpoints.py` generate candidate subdomains/endpoints without an LLM, so discovery never depends on API availability.

## Pipeline phases

1. **Discovery** — subfinder + crt.sh + dnsx + httpx → live hosts, with deterministic subdomain permutation.
2. **Surface mapping** — katana + gau (+ feroxbuster on monthly) + x8 + auth probing → ranked URL set.
3. **Vulnerability scan** — nuclei (targeted + broad) + gf patterns + JS secrets + API probes, with WAF-envelope detection to skip doomed scans.
4. **Synthesis** — wordlist mining + `synthesis_aggregator.py` + the recon profile (or direct-API gate) → `final_report.md` + updated `target_knowledge.json`.

## Quick start

```bash
git clone https://github.com/vanmanhacks/spice-harvester.git
cd spice-harvester
cp .env.example .env        # add DEEPSEEK_API_KEY (+ optional SIGNAL_* for alerts)
docker volume create wordlists
docker compose up -d --build
echo "*.example.com" > scope.txt
python3 pipeline/run.py monthly --force
```

### Optional: self-improving AI layer

Route suggestion + synthesis through a dedicated Hermes `recon` profile whose
memory persists and sharpens across scans:

```bash
./recon-profile/setup.sh recon <your-DEEPSEEK-API-key>
echo "AI_ENABLED=1" >> .env
```

Without `AI_ENABLED`, the pipeline runs deterministic-only (no AI suggestion) with
direct-API synthesis — the safe default.

## Configuration

- `scope.txt` — target domains, one per line (`*.example.com` wildcards supported).
- `.env` — API keys and alerting (see `.env.example`; never commit real secrets).
- Output lands in `pipeline/output/<domain>/monthly/` (gitignored).

## Deployment

- **Docker Compose** — `docker-compose.yml` (recon-runner, warden Squid scope-enforcer, docker-socket-proxy).
- **NixOS** — `spice-harvester.nix` + `flake.nix` provide systemd services/timers for both tiers, an OPSEC exit-node precondition, and a weekly-skips-if-monthly-running guard.

## OPSEC

Run recon only against targets you are authorized to test. The framework is designed to route traffic through a VPN/exit node; that precondition is enforced declaratively in the NixOS module and asserted at pipeline start.

## License

MIT — see [LICENSE](LICENSE).
