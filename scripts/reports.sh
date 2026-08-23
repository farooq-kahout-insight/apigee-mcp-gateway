#!/usr/bin/env bash
# Idempotent: the three Apigee Analytics custom reports the spec asks for --
# requests per app, error rate per proxy, latency per target.
#
# These answer a different question from the Cloud Logging audit and are not a
# substitute for it. Analytics is sampled, aggregated and retained on Apigee's
# own schedule; it tells you that error rates moved. The audit log is the
# per-request record of who did what, and it is what an incident is actually
# reconstructed from. Both exist because "is something wrong" and "what exactly
# happened" are different jobs.
#
# One deviation from the spec, stated because it is a real gap rather than a
# detail: the custom-report API has no percentile function. It accepts only
# sum, avg, min, max and friends, and -- worth knowing -- it does not validate
# metric names at all, so inventing "p95_total_response_time" yields a report
# that is created successfully and then renders nothing. So the target report
# carries avg and max here, and true p95 is computed from the audit log by
# tests/latency_p95.py, which has the per-request numbers to do it honestly.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/../config/env.sh"

TOKEN="$(token)"
[ -n "$TOKEN" ] || { echo "FATAL: no gcloud access token. Run: gcloud auth login" >&2; exit 1; }

BASE="https://apigee.googleapis.com/v1/organizations/$APIGEE_ORG/reports"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# No "comments" or "tags" on the bodies below, though the API accepts both
# without complaint: it drops them on update, so they would appear on a first
# creation and silently vanish on the next run of this script. A field that only
# survives until someone reruns the provisioning is worse than an absent one.
# The explanation lives here instead, where it stays put.

# Existing reports by display name, so a rerun updates rather than duplicates.
curl -sS -H "Authorization: Bearer $TOKEN" "$BASE" > "$TMP/existing.json"

id_for() {
  python -c "
import json, sys
want = sys.argv[1]
data = json.load(open(sys.argv[2]))
for report in data.get('qualifier') or []:
    if report.get('displayName') == want:
        print(report.get('name')); break
" "$1" "$TMP/existing.json"
}

upsert() { # display-name body-file
  local name="$1" body="$2" id
  id="$(id_for "$name")"
  if [ -n "$id" ]; then
    echo "==> updating report: $name"
    curl -sS -X PUT -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
      --data-binary "@$body" "$BASE/$id" >/dev/null
  else
    echo "==> creating report: $name"
    curl -sS -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
      --data-binary "@$body" "$BASE" >/dev/null
  fi
}

# ------------------------------------------------- requests per app
# developer_app is the agent identity: the same app name VerifyAPIKey resolves
# the key to, and the same one the audit record carries as "agent". So this
# chart and the audit log can be read against each other.
cat > "$TMP/apps.json" <<JSON
{
  "displayName": "Agent Airlock: requests per agent",
  "chartType": "column",
  "metrics": [ { "name": "message_count", "function": "sum" } ],
  "dimensions": [ "developer_app" ],
  "sortByCols": [ "message_count" ],
  "sortOrder": "DESC",
  "timeUnit": "hour"
}
JSON
upsert "Agent Airlock: requests per agent" "$TMP/apps.json"

# ------------------------------------------------- error rate per proxy
# message_count alongside is_error rather than is_error on its own: a raw count
# of errors is unreadable without the denominator, and the ratio is the thing
# anyone actually wants.
cat > "$TMP/errors.json" <<JSON
{
  "displayName": "Agent Airlock: error rate per proxy",
  "chartType": "column",
  "metrics": [
    { "name": "is_error", "function": "sum" },
    { "name": "message_count", "function": "sum" }
  ],
  "dimensions": [ "apiproxy" ],
  "sortByCols": [ "is_error" ],
  "sortOrder": "DESC",
  "timeUnit": "hour"
}
JSON
upsert "Agent Airlock: error rate per proxy" "$TMP/errors.json"

# ------------------------------------------------- latency per target
# Both target_response_time and total_response_time, because the gap between
# them is the gateway's own overhead -- the cost of every policy in the chain,
# which is the number to watch when adding one.
cat > "$TMP/latency.json" <<JSON
{
  "displayName": "Agent Airlock: latency per target",
  "chartType": "line",
  "metrics": [
    { "name": "target_response_time", "function": "avg" },
    { "name": "target_response_time", "function": "max" },
    { "name": "total_response_time", "function": "avg" }
  ],
  "dimensions": [ "target_host" ],
  "sortByCols": [ "target_response_time" ],
  "sortOrder": "DESC",
  "timeUnit": "hour"
}
JSON
upsert "Agent Airlock: latency per target" "$TMP/latency.json"

echo
echo "Reports live at:"
echo "  https://console.cloud.google.com/apigee/analytics/custom-reports?project=$APIGEE_ORG"
