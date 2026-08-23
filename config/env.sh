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

# The identity the deployed proxies and shared flows run as. It exists solely so
# MessageLogging can write to Cloud Logging; it holds roles/logging.logWriter and
# nothing else, so a bug in a policy cannot reach any other Google API. Created
# by scripts/provision.sh.
export APIGEE_DEPLOY_SA="${APIGEE_DEPLOY_SA:-apigee-airlock-logger@${APIGEE_ORG}.iam.gserviceaccount.com}"
export AUDIT_LOG_NAME="${AUDIT_LOG_NAME:-agent-airlock-audit}"

# apigeecli lives in ~/bin; gcloud supplies the control-plane token.
export PATH="$HOME/bin:$PATH"
token() { gcloud auth print-access-token --project "$APIGEE_ORG" 2>/dev/null; }
export -f token
