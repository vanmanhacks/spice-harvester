#!/usr/bin/env bash
# synthesis_rerun.sh — Re-run the synthesis gate after a nuclei backfill so the
# fresh nuclei_results.json findings are folded into final_report.md.
#
# Regenerates synthesis_input.json (aggregator, in-container) then re-runs the
# AI gate (hermes_recon.py synthesize, host) with the recon profile (fallback
# to the direct DeepSeek API). Pair with nuclei_backfill.sh: backfill first,
# then this.
#
# Usage: bash pipeline/synthesis_rerun.sh [domain ...]
#   (no args => bill.com divvy.co 2go.com)

set -u
SPICE_HOME="${SPICE_HARVESTER_HOME:-/opt/spice-harvester}"
CONTAINER="spice-harvester-recon-runner"
[ -f /etc/spice-harvester/env ] && { set -a; source /etc/spice-harvester/env; set +a; }
export SPICE_HARVESTER_HOME="$SPICE_HOME"

DOMAINS=("$@")
[ ${#DOMAINS[@]} -eq 0 ] && DOMAINS=(bill.com divvy.co 2go.com)

for domain in "${DOMAINS[@]}"; do
  d="$SPICE_HOME/pipeline/output/$domain/monthly"
  [ -f "$d/live_hosts.json" ] || { echo "[-] $domain: no live_hosts.json — skip"; continue; }

  echo "[*] $domain: regenerating synthesis_input.json"
  docker exec -i "$CONTAINER" python3 /app/scripts/synthesis_aggregator.py "/app/output/$domain/monthly"

  echo "[*] $domain: synthesis gate"
  python3 "$SPICE_HOME/pipeline/scripts/hermes_recon.py" synthesize "$d" "$domain"
  if [ -s "$d/final_report.md" ]; then
    echo "[+] $domain: final_report.md refreshed ($(wc -l < "$d/final_report.md") lines)"
  else
    echo "[!] $domain: no report written"
  fi
done
