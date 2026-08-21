#!/usr/bin/env bash
# Sourced by every script. Loads .env if present, then exports defaults.
set -o allexport
if [ -f "$(dirname "${BASH_SOURCE[0]}")/../.env" ]; then
  . "$(dirname "${BASH_SOURCE[0]}")/../.env"
fi
set +o allexport

export APIGEE_ORG="${APIGEE_ORG:-your-gcp-project-id}"
export APIGEE_ENV="${APIGEE_ENV:-eval}"
export APIGEE_ENVGROUP="${APIGEE_ENVGROUP:-eval-group}"
export APIGEE_HOST="${APIGEE_HOST:-YOUR_LB_IP.nip.io}"
export APIGEE_BASE="https://${APIGEE_HOST}"

# apigeecli lives in ~/bin; gcloud supplies the control-plane token.
export PATH="$HOME/bin:$PATH"
token() { gcloud auth print-access-token --project "$APIGEE_ORG" 2>/dev/null; }
export -f token
