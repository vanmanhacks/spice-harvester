# Spice Harvester — Architecture

```mermaid
flowchart TB
    subgraph Sched["Scheduling (systemd)"]
        MT["spice-harvester-monthly-deep<br/>1st Sunday 02:00 · ~12–18h"]
        WT["spice-harvester-weekly-light<br/>Sunday 08:00 · ~2h · skips if monthly active"]
    end

    MT --> DRV
    WT --> DRV

    DRV["**pipeline/run.py**<br/>Python orchestrator<br/>(flock serialization, per-domain isolation,<br/>scope validation, graceful alerts)"]

    subgraph Phases["Pipeline phases"]
        direction LR
        P1["1 · Discovery<br/>subfinder · crt.sh · dnsx · httpx<br/>permute_subdomains + recon profile*"]
        P2["2 · Surface<br/>katana · gau · ferox* · x8 · auth<br/>permute_endpoints + recon profile*"]
        P3["3 · Vuln scan<br/>nuclei · gf · JS secrets · API<br/>WAF-envelope skip"]
        P4["4 · Synthesis<br/>wordlists · aggregator · recon profile*"]
        P1 --> P2 --> P3 --> P4
    end

    DRV --> P1

    subgraph Docker["Docker (network_mode: host)"]
        RC["**recon-runner**<br/>subfinder nuclei httpx katana gau<br/>feroxbuster x8 gf dnsx"]
        WD["**warden**<br/>Squid scope-enforcer<br/>(127.0.0.1:3128)"]
        SP["docker-socket-proxy"]
    end

    P1 -. docker exec .-> RC
    P2 -. docker exec .-> RC
    P3 -. docker exec .-> RC

    RP["**Hermes recon profile**<br/>suggestion + synthesis<br/>persistent, self-improving memory"]
    DS["DeepSeek API<br/>deepseek-flash<br/>(direct-API fallback)"]

    P1 -->|AI_ENABLED=1| RP
    P2 -->|AI_ENABLED=1| RP
    P4 -->|AI_ENABLED=1| RP
    RP -. fallback on failure .-> DS
    P4 -->|final_report.md| OUT["pipeline/output/&lt;domain&gt;/monthly/"]
    DRV -->|completion alerts| SG["signal-cli"]
    DRV --> SCOPE["scope.txt"]
    DRV --> ENV[".env / /etc/spice-harvester/env<br/>DEEPSEEK_API_KEY · AI_ENABLED · SIGNAL_*"]
```

## Component notes

| Layer | Component | Role |
|---|---|---|
| Orchestrator | `pipeline/run.py` | Python driver; two tiers (`monthly` deep / `weekly` light); per-target `flock`; scope validation; per-domain exception isolation |
| Discovery | subfinder, crt.sh, dnsx, httpx | Subdomain enumeration + liveness (+ tech/CDN detection for synthesis and WAF envelope) |
| Enrichment | `permute_subdomains.py`, `permute_endpoints.py` | Deterministic (no-LLM) candidate generation — always runs |
| AI layer | Hermes `recon` profile, `hermes_recon.py` | Agent-driven suggestion + synthesis with persistent memory (`AI_ENABLED=1`); falls back to `ai_suggest.py` / `synthesis_gate.py` on failure |
| Surface | katana, gau, feroxbuster (monthly), x8 | URL + parameter + auth-endpoint discovery |
| Vuln | nuclei (targeted + broad), gf, `js_secrets.py`, API probes | Finding triage; WAF-envelope detection skips doomed scans |
| Synthesis | `synthesis_aggregator.py`, `synthesis_gate.py` | Aggregates scan output → single gate → `final_report.md` |
| Containers | recon-runner, warden, docker-socket-proxy | All tools run in the recon container; warden enforces scope; socket-proxy mediates the Docker API |
| Alerts | signal-cli | Pipeline start/failure/completion notifications |

`*` feroxbuster and the broad nuclei pass run only on the monthly tier. The recon profile is created with `./recon-profile/setup.sh`; see `recon-profile/README.md`.
