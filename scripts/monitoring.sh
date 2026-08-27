#!/usr/bin/env bash
# Idempotent: the Cloud Logging metrics and the alert policies that watch the
# audit stream. Separate from deploy.sh because these live in the Google Cloud
# project rather than in Apigee, and because they only need re-running when the
# audit schema or the alerting thresholds change.
#
# Two alarms, watching two different kinds of runaway agent.
#
# The github one is deliberately about *attempts*, not successes: an agent that
# tries to open 25 issues in an hour is worth a human's attention whether or not
# the gateway let any of them through. A refusal loop is the signature of a
# prompt injection running into policy, which is exactly the thing worth paging
# on.
#
# The llm one takes the opposite emphasis, and only served calls can contribute
# to it, because a refused model request never reaches the upstream and costs
# nothing. What that alarm watches is money leaving, not intent.
#
# Both are per-identity, so one runaway agent trips its own alarm without the
# other's ordinary traffic diluting it, and the incident names who did it.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/../config/env.sh"

TOKEN="$(token)"
[ -n "$TOKEN" ] || { echo "FATAL: no gcloud access token. Run: gcloud auth login" >&2; exit 1; }

METRIC="${AUDIT_METRIC:-airlock_github_writes}"
POLICY_TITLE="Agent Airlock: GitHub write attempts above 20/hour"
# Comma-separated display names. Both alarms fan out to all of them, which is
# why this replaced the single ALERT_CHANNEL_TITLE it still honours.
#
# Slack alone by default, because that is where these get *seen*: a quota breach
# or a burst of denied writes is something somebody should look at within
# minutes, and an alarm that lands in a mailbox nobody reads during an incident
# is an alarm that did not fire. The cost of dropping email is real and worth
# naming: one delivery path is one point of silence, and a workspace that gets
# archived, left, or rate-limited takes the alerting with it. Add it back for a
# deployment that cares more about durability than latency:
#   ALERT_CHANNEL_TITLES="ai-gateway-alerts,Email Alert" bash scripts/monitoring.sh
#
# The default is the channel's *Monitoring display name*, which is matched
# literally and is not the same string as the Slack channel it posts to. They
# happen to coincide here because the console seeds the display name from the
# channel; renaming either one in the console silently unwires the alarms, which
# is why the lookup below prints what it could not find instead of skipping it.
#
# #ai-gateway-alerts is deliberately not the channel the gateway itself is
# allowlisted to read and post in. Alerting about an agent through the same
# channel that agent can write to is a loop worth not building.
CHANNEL_TITLES="${ALERT_CHANNEL_TITLES:-${ALERT_CHANNEL_TITLE:-ai-gateway-alerts}}"
THRESHOLD="${AUDIT_ALERT_THRESHOLD:-20}"

LLM_METRIC="${LLM_AUDIT_METRIC:-airlock_llm_tokens}"
# Low enough that a demo can trip it on purpose inside one hour of ordinary
# traffic, high enough that a single question to a model does not. The github
# threshold is set on the same principle: an alarm nobody has ever seen fire is
# an alarm nobody trusts.
LLM_THRESHOLD="${LLM_ALERT_THRESHOLD:-2000}"
LLM_POLICY_TITLE="Agent Airlock: model spend above $LLM_THRESHOLD tokens/hour"

api() { # method url [body-file]
  local method="$1" url="$2" body="${3:-}"
  if [ -n "$body" ]; then
    curl -sS -X "$method" -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
      --data-binary "@$body" "$url"
  else
    curl -sS -X "$method" -H "Authorization: Bearer $TOKEN" "$url"
  fi
}

MET_URL="https://logging.googleapis.com/v2/projects/$APIGEE_ORG/metrics"
POL_URL="https://monitoring.googleapis.com/v3/projects/$APIGEE_ORG/alertPolicies"

upsert_metric() { # name body-file
  # The response is read, not discarded. Throwing it away is how this script
  # spent a run announcing "creating log metric airlock_llm_tokens", creating
  # nothing (the API was rejecting the body), and then blaming the missing
  # metric on Monitoring's propagation delay for eight minutes -- a failure that
  # printed two lies and exited 0.
  local out
  if api GET "$MET_URL/$1" | grep -q '"name"'; then
    echo "==> updating log metric $1"
    out="$(api PUT "$MET_URL/$1" "$2")"
  else
    echo "==> creating log metric $1"
    out="$(api POST "$MET_URL" "$2")"
  fi
  if ! printf '%s' "$out" | grep -q '"name"'; then
    echo "$out" >&2
    echo "FATAL: log metric '$1' was not written" >&2
    return 1
  fi
}

upsert_policy() { # display-title body-file
  local existing
  existing="$(api GET "$POL_URL" | python -c "
import sys, json
want = sys.argv[1]
for p in json.load(sys.stdin).get('alertPolicies', []):
    if p.get('displayName') == want:
        print(p['name']); break
" "$1")"
  if [ -n "$existing" ]; then
    echo "==> updating alert policy $existing"
    # $existing is a resource name ("projects/.../alertPolicies/123"), not a URL.
    # An earlier version passed it to curl as-is, which resolved the host as
    # "projects" and failed -- so the policy was created once and every rerun
    # since then quietly changed nothing, including reruns meant to correct the
    # runbook text an on-call reads at 3am.
    #
    # The response is checked for the same reason upsert_metric checks its own:
    # an unread PATCH reply is how this script reported success while rewiring
    # nothing. The specific failure was a 500 carrying "Quota exceeded ...
    # Control requests per minute per user" from logging.googleapis.com --
    # Monitoring re-reads the log-based metric behind the policy on every PATCH,
    # so a run that touches two metrics and two policies can trip a per-minute
    # control-plane quota that has nothing to do with the alarm being correct.
    # It is transient by definition, so it is retried rather than treated as
    # fatal, and anything else still fails loudly.
    local i out
    for i in 1 2 3 4 5; do
      out="$(api PATCH "https://monitoring.googleapis.com/v3/$existing?updateMask=displayName,documentation,combiner,enabled,conditions,alertStrategy,notificationChannels" "$2")"
      if printf '%s' "$out" | grep -q '"name"'; then
        printf '%s' "$out" | python -c "import sys,json; print('   ', json.load(sys.stdin)['name'])"
        return 0
      fi
      if ! printf '%s' "$out" | grep -q 'Quota exceeded'; then
        echo "$out" >&2
        echo "FATAL: alert policy '$1' was not updated" >&2
        return 1
      fi
      echo "    control-plane quota exceeded; retrying in 30s ($i/5)"
      sleep 30
    done
    echo "$out" >&2
    echo "FATAL: '$1' still quota-limited after 5 attempts. Re-run this script." >&2
    return 1
  else
    echo "==> creating alert policy"
    # A policy cannot be created before Monitoring has seen the metric it names,
    # and a log-based metric does not exist to Monitoring the moment Logging
    # accepts it -- the descriptor takes minutes to propagate, longer if no
    # matching log line has been written yet. So the first run of this script on
    # a fresh project reliably fails here while the second one succeeds, which
    # is exactly the kind of failure an operator learns to ignore.
    #
    # It is retried rather than ignored, and a persistent failure is fatal:
    # printing the API's error and exiting 0, as this did once, left a metric
    # with no alarm on it and a script that said it was finished.
    local i out
    for i in 1 2 3 4 5 6 7 8; do
      out="$(api POST "$POL_URL" "$2")"
      if printf '%s' "$out" | grep -q '"name"'; then
        printf '%s' "$out" | python -c "import sys,json; print('   ', json.load(sys.stdin)['name'])"
        return 0
      fi
      if ! printf '%s' "$out" | grep -q 'Cannot find metric'; then
        echo "$out" >&2
        echo "FATAL: could not create alert policy '$1'" >&2
        return 1
      fi
      echo "    metric descriptor has not propagated yet; retrying in 60s ($i/8)"
      sleep 60
    done
    echo "$out" >&2
    echo "FATAL: '$1' still cannot see its metric after 8 minutes. Re-run this script." >&2
    return 1
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

upsert_metric "$METRIC" "$TMP/metric.json"

# ------------------------------------------------------------------ channels
#
# Channels are looked up, never created -- but not because they cannot be. The
# Monitoring API will create a Slack channel from a bot token: POST a channel of
# type "slack" with an auth_token and Google forwards it to Slack's auth.test,
# returning Slack's own verdict ("invalid_auth" for a bad one). Creation is
# withheld here anyway, because the token that would go in it is the same bot
# token the gateway injects from the KVM, and copying it into a second system
# doubles both the blast radius and the number of places a rotation has to
# reach. The console's "Add Slack channel" mints a token belonging to Google's
# own Slack app instead, which is a credential this project never holds.
#
# So this script resolves names to resource IDs and says loudly which ones it
# could not find, rather than pretending to provision a channel and silently
# producing an alarm that rings nowhere. That failure mode -- an alert policy
# wired to an empty channel list -- looks healthy in every dashboard and is
# discovered during the incident it was supposed to warn about.
CHANNEL_JSON="$(api GET "https://monitoring.googleapis.com/v3/projects/$APIGEE_ORG/notificationChannels")"
RESOLVED="$(printf '%s' "$CHANNEL_JSON" | python -c 'import sys, json
wanted = [w.strip() for w in sys.argv[1].split(",") if w.strip()]
found = {}
for c in json.load(sys.stdin).get("notificationChannels", []):
    name = c.get("displayName")
    if name in wanted and name not in found:
        found[name] = c["name"]
for w in wanted:
    print(("OK\t%s\t%s" % (w, found[w])) if w in found else ("MISSING\t%s\t" % w))
' "$CHANNEL_TITLES")"

CHANNELS='[]'
CHANNEL_IDS=""
while IFS="$(printf '\t')" read -r state title id; do
  [ -z "$state" ] && continue
  if [ "$state" = "OK" ]; then
    echo "==> notification channel '$title' -> $id"
    CHANNEL_IDS="$CHANNEL_IDS${CHANNEL_IDS:+,}\"$id\""
  else
    echo "WARN: no notification channel named '$title'." >&2
    case "$title" in
      *[Ss]lack*)
        echo "      Add one in the Monitoring console: Alerting -> Edit notification" >&2
        echo "      channels -> Slack -> Add new, authorize the workspace, and name it" >&2
        echo "      exactly '$title'. Then re-run this script." >&2 ;;
    esac
  fi
done <<EOF
$RESOLVED
EOF

if [ -n "$CHANNEL_IDS" ]; then
  CHANNELS="[$CHANNEL_IDS]"
else
  echo "WARN: no channels resolved; the policies will alert to nobody." >&2
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

upsert_policy "$POLICY_TITLE" "$TMP/policy.json"

# ----------------------------------------------------------- llm token metric
#
# The one metric here whose *value* is not 1. valueExtractor pulls the token
# count out of the record, so summing the series gives tokens rather than calls
# -- which is the number that corresponds to money, and the number a per-call
# counter cannot recover: ten one-word questions and one enormous document
# summary are the same count and nothing like the same bill.
#
# The filter names tokens_total rather than resting on the action alone.
# audit.js omits that field entirely on any call that did not reach the
# upstream, and a record with no value would be extracted as a zero -- filling
# the series with points that mean "refused" while reading as "free".
#
# DISTRIBUTION rather than INT64, and not by preference: Cloud Logging accepts a
# valueExtractor only on a distribution metric ("A value extractor can only be
# specified for a DISTRIBUTION value type"), so an INT64 metric here could only
# ever have counted calls. The buckets are wide enough (1 to 2^64, doubling) that
# no plausible call lands outside them, which matters because a value past the
# last bucket is summed at the bucket bound rather than at its own size.
#
# The cost of that forced choice is paid one section down: a distribution cannot
# be compared to a number, so the alarm has to convert it to a scalar first, and
# a plain threshold condition has no way to spell "the sum of the values".
cat > "$TMP/llm_metric.json" <<JSON
{
  "name": "$LLM_METRIC",
  "description": "Tokens spent on model calls through the gateway, per agent identity. Only served calls contribute; a refused model request never reaches the upstream and costs nothing.",
  "filter": "logName=\"projects/$APIGEE_ORG/logs/$AUDIT_LOG_NAME\" AND jsonPayload.action=\"llm.chat\" AND jsonPayload.tokens_total>0",
  "metricDescriptor": {
    "metricKind": "DELTA",
    "valueType": "DISTRIBUTION",
    "unit": "1",
    "displayName": "Airlock LLM tokens spent",
    "labels": [
      { "key": "agent", "valueType": "STRING", "description": "Apigee app that presented the key" },
      { "key": "model", "valueType": "STRING", "description": "Model the upstream reported serving" }
    ]
  },
  "bucketOptions": {
    "exponentialBuckets": { "numFiniteBuckets": 64, "growthFactor": 2, "scale": 1 }
  },
  "valueExtractor": "EXTRACT(jsonPayload.tokens_total)",
  "labelExtractors": {
    "agent": "EXTRACT(jsonPayload.agent)",
    "model": "EXTRACT(jsonPayload.model)"
  }
}
JSON
upsert_metric "$LLM_METRIC" "$TMP/llm_metric.json"

# ----------------------------------------------------------- llm spend policy
#
# Grouped by agent only, not by model. The question this alarm answers is "who
# is spending", and an agent that has scattered the same budget across four
# models is exactly the case a per-model breakdown would hide by keeping every
# series under the threshold. The model label is still on the metric, so that
# breakdown is one grouping change away in the console when someone wants it.
#
# MQL rather than the threshold condition the github alarm uses, because the
# metric it watches is a distribution and Monitoring refuses to compare one to a
# number: "a time series of type DISTRIBUTION cannot be compared directly to a
# literal numeric threshold without first converting to a scalar via an explicit
# aligner such as ALIGN_PERCENTILE_50". The scalar aligners on offer are
# percentiles, a mean and a count -- every one of them a statement about the size
# of a typical call, and none of them the total. That distinction is the whole
# alarm: a hundred small calls and one large one cost the same money and have
# wildly different percentiles. MQL's sum() over a distribution column returns
# the sum of the values as a Double, which is the number that corresponds to the
# bill, and it is the only spelling of it available here.
#
# The window is a sliding hour evaluated every minute, not a clock-hour bucket:
# an agent that burns the budget at 14:59 should page then, not at the top of the
# next hour. That is why the aligner is delta_gauge() with a separate `window`
# rather than the more obvious delta(1h) -- delta insists the window equal the
# period ("its alignment window of 1h differs from the alignment period of 1m"),
# which forces the choice between a sliding window and a fast one.
cat > "$TMP/llm_policy.json" <<JSON
{
  "displayName": "$LLM_POLICY_TITLE",
  "documentation": {
    "content": "An agent identity spent more than $LLM_THRESHOLD model tokens in one hour through the Agent Airlock gateway.\n\nUnlike the GitHub write alarm this counts only calls that were actually served: a model the allowlist refused never reached the upstream and cost nothing. So this firing means budget genuinely left.\n\nTo see the calls: in Logs Explorer, filter logName=\"projects/$APIGEE_ORG/logs/$AUDIT_LOG_NAME\" and jsonPayload.action=\"llm.chat\". Each record carries the agent, the model served and the prompt/completion split. No prompt or completion text is logged, by design -- if the question is *what* was asked, this audit cannot answer it and is not meant to.\n\nTo slow one agent without touching the other, lower its API product's llm_quota attribute; to stop a model being spent on at all, remove it from gateway-config/llm_allowed_models in the KVM. Neither needs the proxy redeployed.",
    "mimeType": "text/markdown"
  },
  "combiner": "OR",
  "enabled": true,
  "conditions": [
    {
      "displayName": "llm.chat tokens > $LLM_THRESHOLD in 1h (per agent)",
      "conditionMonitoringQueryLanguage": {
        "query": "fetch global::logging.googleapis.com/user/$LLM_METRIC\n| align delta_gauge()\n| every 1m\n| window 1h\n| group_by [agent], [tokens: sum(value.$LLM_METRIC)]\n| condition tokens > $LLM_THRESHOLD",
        "duration": "0s",
        "trigger": { "count": 1 }
      }
    }
  ],
  "alertStrategy": { "autoClose": "1800s" },
  "notificationChannels": $CHANNELS
}
JSON
upsert_policy "$LLM_POLICY_TITLE" "$TMP/llm_policy.json"
