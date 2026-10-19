#!/usr/bin/env bash
# Pull the current brand tokens from the vfrazier.app site repo so the notes
# always match the site. Usage: scripts/sync-tokens.sh [path-to-vfrazier-app]
set -euo pipefail
cd "$(dirname "$0")/.."
SRC="${1:-}"
if [ -z "$SRC" ]; then
  SRC=$(mktemp -d); trap 'rm -rf "$SRC"' EXIT
  git clone -q --depth 1 https://github.com/frazier-at-cpcc/vfrazier-app "$SRC"
fi
{ echo "/* Copied verbatim from frazier-at-cpcc/vfrazier-app src/styles/tokens.css."
  echo "   Keep in sync with the site: scripts/sync-tokens.sh pulls the latest copy. */"
  cat "$SRC/src/styles/tokens.css"; } > styles/tokens.css
git diff --stat -- styles/tokens.css || true
