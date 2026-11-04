{ config, pkgs, ... }:

{
  programs.zsh.shellAliases = {
    # ─── Spice Harvester — Offensive Security Framework ───
    SPICE_HARVESTER = "/opt/spice-harvester";
    OM = "/opt/other-memory";

    spice-harvester-up = "cd $SPICE_HARVESTER && docker compose ps";
    spice-harvester-ops = "hermes --profile recon -s spice-harvester-recon chat -q 'Run OPSEC pre-flight checks. Verify VPN, kill switch, scope enforcement.'";
    spice-harvester-recon = "hermes --profile recon -s spice-harvester-orchestrator chat -q 'Full engagement pass on scope.txt. Run 2-tier pipeline analysis.'";
    spice-harvester-findings = "cat $SPICE_HARVESTER/pipeline/output/latest/confirmed_findings.json 2>/dev/null | python3 -m json.tool | head -40";
    spice-harvester-logs = "sudo journalctl -u spice-harvester-daily-light -n 30 --no-pager";
    spice-harvester-trigger-daily = "systemctl --user start spice-harvester-daily-light.service";
    spice-harvester-trigger-weekly = "systemctl --user start spice-harvester-weekly-deep.service";
    spice-harvester-status = "systemctl --user status spice-harvester-daily-light.service spice-harvester-weekly-deep.service --no-pager -n 0";

    # ─── Other Memory — Search & Crawl ───
    om-status = "cd $OM && docker compose ps";
    om-search = "hermes chat -q 'Use web_search to find'";

    # ─── Stack Overview ───
    stack-status = ''
      echo "=== Spice Harvester ===" && docker compose -f $SPICE_HARVESTER/docker-compose.yml ps --format "table {{.Name}}\t{{.Status}}" 2>/dev/null
      echo "=== Other Memory ===" && docker compose -f $OM/docker-compose.yml ps --format "table {{.Name}}\t{{.Status}}" 2>/dev/null
      echo "=== Hermes ===" && hermes doctor 2>/dev/null | head -5
    '';
  };
}
