#!/usr/bin/env bash
# Spice Harvester — Hermes recon profile setup.
#
# Creates a dedicated Hermes profile that provides the AI layer (suggestion +
# synthesis) with persistent, self-improving memory. Safe to re-run (idempotent).
#
# Usage:
#   ./setup.sh [profile-name] [deepseek-api-key]
#
# The API key is required. It is resolved from, in order: the 2nd argument,
# DEEPSEEK_API_KEY in your shell, or a real value in ~/.hermes/.env.
# A profile does NOT inherit the default profile's ~/.hermes/.env key.
set -euo pipefail

PROFILE="${1:-recon}"
KEY="${2:-${DEEPSEEK_API_KEY:-}}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROFILE_DIR="$HOME/.hermes/profiles/$PROFILE"

# 0. Validate the profile name (plain identifier — prevents path traversal)
if [[ ! "$PROFILE" =~ ^[a-z0-9][a-z0-9_-]*$ ]]; then
  echo "ERROR: invalid profile name '$PROFILE' (must match ^[a-z0-9][a-z0-9_-]*$)" >&2
  exit 2
fi

if ! command -v hermes >/dev/null 2>&1; then
  echo "ERROR: hermes not found on PATH — install Hermes first" >&2
  echo "  curl -fsSL https://hermes-agent.nousresearch.com/install.sh | bash" >&2
  exit 1
fi

# 1. Create the profile (idempotent). --no-skills: don't seed the bundled
#    generalist skill families — this is a purpose-built recon agent.
if [[ ! -d "$PROFILE_DIR" ]]; then
  echo "[*] Creating Hermes profile '$PROFILE'"
  hermes profile create "$PROFILE" --no-skills \
    --description "Spice Harvester recon agent — AI suggestion + synthesis"
fi
mkdir -p "$PROFILE_DIR/skills"

# 2. Model config — overwritten every run: `hermes profile create` seeds a
#    default (deepseek-v4-pro) config, which must be replaced with the recon
#    pin (deepseek-flash) + the MINIMAL toolset. The agent needs `memory`
#    (persistence) and `skills` (the `-s` flag loads the recon skills); the
#    dangerous toolsets — terminal / code_execution / file / browser / web —
#    are all disabled, which is the injection-safety guarantee.
#    Preserve _config_version so Hermes doesn't flag the config as pre-v12.
CONFIG_VERSION=""
if [[ -f "$PROFILE_DIR/config.yaml" ]]; then
  CONFIG_VERSION="$(grep -m1 '^_config_version:' "$PROFILE_DIR/config.yaml" || true)"
fi
cat > "$PROFILE_DIR/config.yaml" <<EOF
model:
  default: deepseek-flash
  provider: deepseek
  temperature: 0.2
  base_url: https://api.deepseek.com/v1
toolsets:
  - memory
  - skills
${CONFIG_VERSION:+$CONFIG_VERSION}
EOF
echo "[*] Wrote $PROFILE_DIR/config.yaml (model: deepseek-flash, toolsets: memory,skills)"

# 3. Task-scoped SOUL.md — this profile is a recon JSON emitter, not a
#    generalist personal assistant. Overwritten every run (task definition).
cat > "$PROFILE_DIR/SOUL.md" <<'EOF'
You are the Spice Harvester recon agent. You emit candidate subdomains and
endpoints as JSON, and synthesize scan output into a concise, evidence-based
security report. You do not run shell commands, browse the web, or edit files
unless the recon task strictly requires it. Output only the requested JSON or
report body — no preamble, no commentary, no "standing by" filler.
EOF
echo "[*] Wrote $PROFILE_DIR/SOUL.md (task-scoped)"

# 4. API key — REQUIRED for the profile's inference (a profile does NOT inherit
#    the default profile's env key). Resolve: arg > shell env > ~/.hermes/.env.
if [[ -z "$KEY" && -f "$HOME/.hermes/.env" ]]; then
  KEY="$(grep -E '^(export[[:space:]]+)?DEEPSEEK_API_KEY=' "$HOME/.hermes/.env" \
         | head -1 | cut -d= -f2- | tr -d '"'"'"'')"
fi
case "$KEY" in
  ""|"***"|"sk-...here")
    echo "ERROR: no DEEPSEEK_API_KEY resolved." >&2
    echo "  Pass it as arg 2, export it in your shell, or set it in ~/.hermes/.env." >&2
    exit 1
    ;;
  *)
    (umask 077; printf 'DEEPSEEK_API_KEY=%s\n' "$KEY" > "$PROFILE_DIR/.env")
    echo "[*] Wrote $PROFILE_DIR/.env (DEEPSEEK_API_KEY)"
    ;;
esac

# 5. Deploy skills. The bundled generalist skills seeded by an earlier
#    `hermes profile create` may be root-owned and undeletable — ignore
#    removal errors and copy ours on top; they are harmless (never loaded
#    for a recon prompt, and the profile has no terminal/file/browser).
rm -rf "$PROFILE_DIR/skills"/* 2>/dev/null || true
cp -r "$SCRIPT_DIR/skills/." "$PROFILE_DIR/skills/"
echo "[*] Deployed skills: $(ls "$PROFILE_DIR/skills" 2>/dev/null | tr '\n' ' ')"

# 6. Report
echo ""
echo "Recon profile '$PROFILE' is ready."
echo "Enable the AI layer in the pipeline by setting AI_ENABLED=1 in the pipeline environment."
echo "For clean memory isolation, use one profile per engagement and set RECON_PROFILE=$PROFILE."
echo "Verify with:  hermes -p $PROFILE chat -q 'reply with OK' --oneshot -Q"
