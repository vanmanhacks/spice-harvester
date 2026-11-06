#!/usr/bin/env bash
# nuclei_backfill.sh — Re-run the nuclei phase with the dedup + narrowed-cves
# fixes on already-scanned domains, filling the 0-findings gap the pre-fix code
# left (nuclei's -o file only grows on findings, so the old output-growth
# watchdog falsely stall-killed it on clean targets).
#
# Run AFTER a monthly scan completes, or standalone. No stall-kill here: nuclei
# runs straight to completion (its -stats stderr is the progress signal).
#
# Usage: bash pipeline/nuclei_backfill.sh [domain ...]
#   (no args => bill.com divvy.co 2go.com)

set -u
SPICE_HOME="${SPICE_HARVESTER_HOME:-/opt/spice-harvester}"
CONTAINER="spice-harvester-recon-runner"
RATE="${NUCLEI_RATE_LIMIT:-15}"

DOMAINS=("$@")
[ ${#DOMAINS[@]} -eq 0 ] && DOMAINS=(bill.com divvy.co 2go.com)

for domain in "${DOMAINS[@]}"; do
  d="$SPICE_HOME/pipeline/output/$domain/monthly"
  [ -f "$d/live_hosts.json" ] || { echo "[-] $domain: no live_hosts.json — skip"; continue; }
  [ -f "$d/high_value_targets.txt" ] || { echo "[-] $domain: no high_value_targets.txt — skip"; continue; }

  echo "[*] $domain: dedup broad host list"
  python3 "$SPICE_HOME/pipeline/scripts/dedup_hosts.py" < "$d/live_hosts.json" > "$d/broad_targets.txt" 2>/dev/null
  broad="$d/broad_targets.txt"
  [ -s "$broad" ] || broad="$d/live_subdomains.txt"
  echo "[*] $domain: broad on $(wc -l < "$broad") backends (from $(wc -l < "$d/live_subdomains.txt") live)"

  echo "[*] $domain: nuclei targeted (critical+high, full templates)"
  docker exec -i "$CONTAINER" nuclei \
    -list "/app/output/$domain/monthly/high_value_targets.txt" \
    -t /root/nuclei-templates/http/cves/ \
    -t /root/nuclei-templates/http/exposed-panels/ \
    -t /root/nuclei-templates/http/misconfiguration/ \
    -t /root/nuclei-templates/http/default-logins/ \
    -t /root/nuclei-templates/http/exposures/ \
    -severity critical,high -rl "$RATE" -bs 2 -c 5 -silent -jsonl \
    -stats -stats-interval 15 \
    -o "/app/output/$domain/monthly/nuclei_targeted.json"

  echo "[*] $domain: nuclei broad (critical, narrowed cves 2025+2026)"
  docker exec -i "$CONTAINER" nuclei \
    -list "/app/output/$domain/monthly/$(basename "$broad")" \
    -t /root/nuclei-templates/http/cves/2025/ \
    -t /root/nuclei-templates/http/cves/2026/ \
    -t /root/nuclei-templates/http/exposed-panels/ \
    -t /root/nuclei-templates/http/misconfiguration/ \
    -severity critical -rl "$RATE" -bs 2 -c 5 -silent -jsonl \
    -stats -stats-interval 15 \
    -o "/app/output/$domain/monthly/nuclei_broad.json"

  docker exec -i "$CONTAINER" bash -c \
    "cat /app/output/$domain/monthly/nuclei_targeted.json /app/output/$domain/monthly/nuclei_broad.json 2>/dev/null | sort -u > /app/output/$domain/monthly/nuclei_results.json"
  echo "[+] $domain: $(wc -l < "$d/nuclei_results.json") nuclei findings written"
done
