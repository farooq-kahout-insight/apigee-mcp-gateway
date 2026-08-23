#!/usr/bin/env bash
# Idempotent: the Cloud Logging metric and the alert policy that watch the audit
# stream. Separate from deploy.sh because these live in the Google Cloud project
# rather than in Apigee, and because they only need re-running when the audit
# schema or the alerting thresholds change.
#
# The alarm this builds is deliberately about *attempts*, not successes: an agent
# that tries to open 25 issues in an hour is worth a human's attention whether or
# not the gateway let any of them through. A refusal loop is the signature of a
# prompt injection running into policy, which is exactly the thing worth paging
# on.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/../config/env.sh"

TOKEN="$(token)"
[ -n "$TOKEN" ] || { echo "FATAL: no gcloud access token. Run: gcloud auth login" >&2; exit 1; }

METRIC="${AUDIT_METRIC:-airlock_github_writes}"
POLICY_TITLE="Agent Airlock: GitHub write attempts above 20/hour"
CHANNEL_TITLE="${ALERT_CHANNEL_TITLE:-Email Alert}"
THRESHOLD="${AUDIT_ALERT_THRESHOLD:-20}"

api() { # method url [body-file]
  local method="$1" url="$2" body="${3:-}"
  if [ -n "$body" ]; then
    curl -sS -X "$method" -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
      --data-binary "@$body" "$url"
  else
    curl -sS -X "$method" -H "Authorization: Bearer $TOKEN" "$url"
  fi
}

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# ---------------------------------------------------------------- log metric
#
# The counter reads jsonPayload, not log labels. That is not a preference: Apigee
# does not expand message templates inside a CloudLogging label value, so a
# metric filtered on labels.action would match every record or none of them
# rather than the writes it names. The payload is the record of record, and the
# three fields used here (action, agent, outcome) are the ones audit.js has
# always emitted, so this is no more fragile than the labels would have been.
cat > "$TMP/metric.json" <<JSON
{
  "name": "$METRIC",
  "description": "Attempts to create a GitHub issue through the gateway, per agent identity and outcome. Counts refusals as well as successes.",
  "filter": "logName=\"projects/$APIGEE_ORG/logs/$AUDIT_LOG_NAME\" AND jsonPayload.action=\"github.issues.create\"",
  "metricDescriptor": {
    "metricKind": "DELTA",
    "valueType": "INT64",
    "unit": "1",
    "displayName": "Airlock GitHub write attempts",
    "labels": [
      { "key": "agent",   "valueType": "STRING", "description": "Apigee app that presented the key" },
      { "key": "outcome", "valueType": "STRING", "description": "ok, denied, throttled, invalid or error" }
    ]
  },
  "labelExtractors": {
    "agent":   "EXTRACT(jsonPayload.agent)",
    "outcome": "EXTRACT(jsonPayload.outcome)"
  }
}
JSON

MET_URL="https://logging.googleapis.com/v2/projects/$APIGEE_ORG/metrics"
if api GET "$MET_URL/$METRIC" | grep -q '"name"'; then
  echo "==> updating log metric $METRIC"
  api PUT "$MET_URL/$METRIC" "$TMP/metric.json" >/dev/null
else
  echo "==> creating log metric $METRIC"
  api POST "$MET_URL" "$TMP/metric.json" >/dev/null
fi

# ------------------------------------------------------------------- channel
CHANNEL="$(api GET "https://monitoring.googleapis.com/v3/projects/$APIGEE_ORG/notificationChannels" \
  | python -c "
import sys, json
want = '''$CHANNEL_TITLE'''
for c in json.load(sys.stdin).get('notificationChannels', []):
    if c.get('displayName') == want:
        print(c['name']); break
")"
if [ -z "$CHANNEL" ]; then
  echo "WARN: no notification channel named '$CHANNEL_TITLE'; the policy will alert to nobody." >&2
  CHANNELS='[]'
else
  echo "==> notification channel $CHANNEL"
  CHANNELS="[\"$CHANNEL\"]"
fi

# -------------------------------------------------------------- alert policy
#
# groupByFields on the agent label means the threshold is per identity: one
# runaway agent trips the alarm without the other's ordinary traffic diluting
# it, and the incident names the agent responsible.
cat > "$TMP/policy.json" <<JSON
{
  "displayName": "$POLICY_TITLE",
  "documentation": {
    "content": "An agent identity attempted more than $THRESHOLD GitHub issue creations in one hour through the Agent Airlock gateway.\n\nThis counts attempts, including refusals. A burst of *denied* attempts is the more interesting case: it is what a prompt-injected agent looks like when it hits policy and keeps trying.\n\nTo see the calls: in Logs Explorer, filter logName=\"projects/$APIGEE_ORG/logs/$AUDIT_LOG_NAME\" and jsonPayload.action=\"github.issues.create\". Each record carries the agent, the repository and the issue title.\n\nTo cut off one agent without touching the other, revoke its key in the Apigee app rather than changing the proxy.",
    "mimeType": "text/markdown"
  },
  "combiner": "OR",
  "enabled": true,
  "conditions": [
    {
      "displayName": "github.issues.create attempts > $THRESHOLD in 1h (per agent)",
      "conditionThreshold": {
        "filter": "metric.type=\"logging.googleapis.com/user/$METRIC\" AND resource.type=\"global\"",
        "aggregations": [
          {
            "alignmentPeriod": "3600s",
            "perSeriesAligner": "ALIGN_SUM",
            "crossSeriesReducer": "REDUCE_SUM",
            "groupByFields": ["metric.label.agent"]
          }
        ],
        "comparison": "COMPARISON_GT",
        "thresholdValue": $THRESHOLD,
        "duration": "0s",
        "trigger": { "count": 1 }
      }
    }
  ],
  "alertStrategy": { "autoClose": "1800s" },
  "notificationChannels": $CHANNELS
}
JSON

POL_URL="https://monitoring.googleapis.com/v3/projects/$APIGEE_ORG/alertPolicies"
EXISTING="$(api GET "$POL_URL" | python -c "
import sys, json
want = '''$POLICY_TITLE'''
for p in json.load(sys.stdin).get('alertPolicies', []):
    if p.get('displayName') == want:
        print(p['name']); break
")"
if [ -n "$EXISTING" ]; then
  echo "==> updating alert policy $EXISTING"
  # $EXISTING is a resource name ("projects/.../alertPolicies/123"), not a URL.
  # An earlier version passed it to curl as-is, which resolved the host as
  # "projects" and failed -- so the policy was created once and every rerun
  # since then quietly changed nothing, including reruns meant to correct the
  # runbook text an on-call reads at 3am.
  api PATCH "https://monitoring.googleapis.com/v3/$EXISTING?updateMask=displayName,documentation,combiner,enabled,conditions,alertStrategy,notificationChannels" "$TMP/policy.json" \
    | python -c "import sys,json; d=json.load(sys.stdin); print('   ', d.get('name', d))"
else
  echo "==> creating alert policy"
  api POST "$POL_URL" "$TMP/policy.json" \
    | python -c "import sys,json; d=json.load(sys.stdin); print('   ', d.get('name', d))"
fi
