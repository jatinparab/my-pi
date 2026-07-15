#!/usr/bin/env bash
# Install this checkout as a global Pi package. Run --update to first fast-forward
# the checkout from origin, then reconcile Pi's package installation.
set -euo pipefail

usage() {
  cat <<'EOF'
Usage: ./install.sh [--update]

Installs the current checkout as a global Pi package, making its extensions
available on this machine.

Options:
  --update  Fast-forward this checkout from origin before installing.
  -h, --help  Show this help.
EOF
}

update=false
case "${1:-}" in
  "") ;;
  --update) update=true ;;
  -h|--help) usage; exit 0 ;;
  *) usage >&2; exit 2 ;;
esac

if ! command -v pi >/dev/null 2>&1; then
  echo "pi is required but was not found on PATH." >&2
  exit 1
fi

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"

if [[ "$update" == true ]]; then
  git -C "$repo_root" pull --ff-only
fi

# pi records the local package path in ~/.pi/agent/settings.json. This is
# idempotent and lets Pi load the package manifest from package.json.
pi install "$repo_root"

echo "Installed my-pi from $repo_root"
echo "Restart Pi or run /reload in an active session to load changes."
