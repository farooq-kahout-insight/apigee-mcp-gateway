#!/usr/bin/env bash
# Import + deploy proxy bundles. Idempotent: creates a new revision and overrides.
# Usage: scripts/deploy.sh [proxy-name ...]   (default: every proxy under proxies/)
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/../config/env.sh"

TOKEN="$(token)"
[ -n "$TOKEN" ] || { echo "FATAL: no gcloud access token. Run: gcloud auth login" >&2; exit 1; }

PROXIES=("$@")
if [ ${#PROXIES[@]} -eq 0 ]; then
  mapfile -t PROXIES < <(find "$HERE/../proxies" -maxdepth 1 -mindepth 1 -type d -printf '%f\n' | sort)
fi

# shared/js is the single source of truth for policy JavaScript; copy it into any
# bundle that has a resources/jsc directory so a deployed resource can never
# drift from the file the unit tests exercise.
sync_js() { # bundle-dir
  [ -d "$HERE/../shared/js" ] || return 0
  [ -d "$1/resources/jsc" ] || return 0
  cp "$HERE/../shared/js"/*.js "$1/resources/jsc/"
}

# Shared flows first -- proxies reference them by name and will fail validation otherwise.
if [ -d "$HERE/../sharedflows" ]; then
  for sf in $(find "$HERE/../sharedflows" -maxdepth 1 -mindepth 1 -type d -printf '%f\n' 2>/dev/null | sort); do
    echo "==> sharedflow $sf"
    sync_js "$HERE/../sharedflows/$sf/sharedflowbundle"
    apigeecli sharedflows create bundle -n "$sf" -f "$HERE/../sharedflows/$sf/sharedflowbundle" \
      -e "$APIGEE_ENV" -o "$APIGEE_ORG" -t "$TOKEN" --ovr --wait --no-warnings
  done
fi

for p in "${PROXIES[@]}"; do
  echo "==> proxy $p"
  sync_js "$HERE/../proxies/$p/apiproxy"
  apigeecli apis create bundle -n "$p" -f "$HERE/../proxies/$p/apiproxy" \
    -e "$APIGEE_ENV" -o "$APIGEE_ORG" -t "$TOKEN" --ovr --wait --no-warnings
done
echo "Deployed: ${PROXIES[*]}"
