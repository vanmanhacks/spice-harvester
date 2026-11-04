{ config, pkgs, lib, ... }:
let
  spiceHarvesterDir = "/opt/spice-harvester";
in
{
  # ─── Host Identity ───
  # Already declared in hardware-configuration.nix / main config.
  # Uncomment ONLY for standalone deployment on a fresh machine.
  # networking.hostName = "spice-harvester";

  # ─── User ───
  # Already declared in main configuration.nix.
  # Uncomment ONLY for standalone deployment.
  # users.users.spice-harvester = {
  #   isNormalUser = true;
  #   extraGroups = [ "wheel" "docker" "networkmanager" ];
  #   initialPassword = "CHANGE_ME_ON_FIRST_BOOT";
  #   password = pkgs.lib.mkForce "!";  # locked — must use initialPassword and change it
  # };

  # ─── Docker ───
  # Already declared in main configuration.nix.
  # Uncomment ONLY for standalone deployment.
  # virtualisation.docker.enable = true;
  # virtualisation.docker.autoPrune.enable = true;
  # virtualisation.docker.autoPrune.dates = "weekly";

  # ─── Tailscale (Remote Admin Only) ───
  services.tailscale.enable = true;

  networking.firewall = {
    trustedInterfaces = [ "tailscale0" ];
    allowedUDPPorts = [ config.services.tailscale.port ];
  };

  # ─── Hermes Agent ───
  # Hermes is managed externally by the llm-agents.nix flake (numtide).
  # It is NOT declared here — the llm-agents.nix module handles the
  # Hermes binary, service, and configuration.
  #
  # Spice Harvester integrates with this pre-configured Hermes instance via:
  #   1. Skills deployed to ~/.hermes/skills/spice-harvester/ (see IMPLEMENTATION-GUIDE)
  #   2. A 'recon' profile created with `hermes profile create recon`
  #   3. Cron jobs registered under the recon profile for daily/weekly gates
  #   4. Signal alerts sent via the signal-cli daemon (Hermes gateway prerequisite)
  #
  # On-demand interactive analysis:
  #   hermes --profile recon -s spice-harvester-recon -s spice-harvester-orchestrator chat -q "..."
  #

  # ─── Docker Compose Stack (Tailscale Mullvad Exit Node) ───
  # Containers use network_mode: "host" and inherit the host's Tailscale
  # Mullvad exit node routing. Kill switch is managed by Tailscale itself:
  #   tailscale set --exit-node-allow-lan-access=false
  # If the Mullvad exit node drops, internet-bound packets hit Tailscale's
  # routing table 52 with no fallback — fail-closed.
  systemd.services.spice-harvester-stack = {
    description = "Spice Harvester Docker Compose Stack (Recon Runner, Warden, Redis)";
    wantedBy = [ "multi-user.target" ];
    after = [ "docker.service" "tailscaled.service" ];
    requires = [ "docker.service" ];
    serviceConfig = {
      Type = "oneshot";
      RemainAfterExit = true;
      WorkingDirectory = "${spiceHarvesterDir}";
      EnvironmentFile = "/etc/spice-harvester/env";
      ExecStartPre = [
        # Fail clearly if the env file is missing.
        "${pkgs.bash}/bin/bash -c 'test -f /etc/spice-harvester/env || { echo \"[!] /etc/spice-harvester/env missing — create it (see .env.example)\"; exit 1; }'"
        # OPSEC precondition: refuse to start recon without a Tailscale exit node.
        "${pkgs.bash}/bin/bash -c 'tailscale status --json 2>/dev/null | grep -q '\"ExitNodeStatus\":{' || { echo \"[!] No Tailscale exit node — refusing to start (OPSEC)\"; exit 1; }'"
      ];
      ExecStart = "${pkgs.docker}/bin/docker compose up -d --build";
      ExecStop = "${pkgs.docker}/bin/docker compose down";
      ExecStopPost = "${pkgs.docker}/bin/docker compose down";
    };
  };

  # ─── Pipeline (2-Tier: Weekly Light + Monthly Deep) ───
  # Weekly: fast scan of new subdomains only (~2h), Sunday 08:00
  # Monthly: full deep scan including feroxbuster (~12-18h), 1st Sunday 02:00
  systemd.services.spice-harvester-weekly-light = {
    description = "Spice Harvester Weekly Light Pipeline (new subdomains only)";
    after = [ "spice-harvester-stack.service" ];
    requires = [ "spice-harvester-stack.service" ];
    serviceConfig = {
      Type = "oneshot";
      User = "spice-harvester";
      WorkingDirectory = "${spiceHarvesterDir}";
      EnvironmentFile = "/etc/spice-harvester/env";
      # Fail clearly if the env file is missing.
      ExecStartPre = "${pkgs.bash}/bin/bash -c 'test -f /etc/spice-harvester/env || { echo \"[!] /etc/spice-harvester/env missing — create it (see .env.example)\"; exit 1; }'";
      # Skip weekly if the monthly deep scan is still running (avoids overlap).
      ExecCondition = "${pkgs.bash}/bin/bash -c '! systemctl is-active --quiet spice-harvester-monthly-deep.service'";
      ExecStart = "${pkgs.python3}/bin/python3 ${spiceHarvesterDir}/pipeline/run.py weekly";
    };
  };

  systemd.timers.spice-harvester-weekly-light = {
    description = "Weekly light scan Sunday at 08:00 UTC";
    wantedBy = [ "timers.target" ];
    timerConfig = {
      OnCalendar = "Sun *-*-* 08:00:00";
      Persistent = true;
    };
  };

  systemd.services.spice-harvester-monthly-deep = {
    description = "Spice Harvester Monthly Deep Pipeline (full scan + feroxbuster)";
    after = [ "spice-harvester-stack.service" ];
    requires = [ "spice-harvester-stack.service" ];
    serviceConfig = {
      Type = "oneshot";
      User = "spice-harvester";
      WorkingDirectory = "${spiceHarvesterDir}";
      EnvironmentFile = "/etc/spice-harvester/env";
      # Fail clearly if the env file is missing.
      ExecStartPre = "${pkgs.bash}/bin/bash -c 'test -f /etc/spice-harvester/env || { echo \"[!] /etc/spice-harvester/env missing — create it (see .env.example)\"; exit 1; }'";
      ExecStart = "${pkgs.python3}/bin/python3 ${spiceHarvesterDir}/pipeline/run.py monthly";
    };
  };

  systemd.timers.spice-harvester-monthly-deep = {
    description = "Monthly deep scan 1st Sunday at 02:00 UTC";
    wantedBy = [ "timers.target" ];
    timerConfig = {
      OnCalendar = "Sun *-*-1..7 02:00:00";
      Persistent = true;
    };
  };

  # ─── Persistent Secrets Directory ───
  # Creates /etc/spice-harvester/ at boot. Place the env file manually after first boot:
  #   scp spice-harvester_env user@your-vps:/etc/spice-harvester/env && chmod 600 /etc/spice-harvester/env
  systemd.tmpfiles.rules = [
    "d /etc/spice-harvester 0700 spice-harvester users - -"
  ];
}
