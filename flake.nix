{
  description = "Spice Harvester — Autonomous Reconnaissance Offensive Security Framework";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    # Hermes Agent is managed externally by numtide/llm-agents.nix flake.
    # Spice Harvester does not declare Hermes as a flake input — it integrates with
    # the pre-configured Hermes instance via skills, profiles, and cron jobs.
    # See spice-harvester.nix comments for integration details.
  };

  outputs = { self, nixpkgs, ... }: {
    nixosConfigurations.spice-harvester = nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        # Generated on target host via nixos-generate-config — not committed to repo
  ./hardware-configuration.nix
        ./spice-harvester.nix
      ];
    };
  };
}
