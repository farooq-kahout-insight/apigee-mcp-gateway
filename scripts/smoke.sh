#!/usr/bin/env bash
# Acceptance / regression suite. Every milestone appends tests; old ones must keep passing.
# Usage: scripts/smoke.sh [milestone-filter]   e.g. scripts/smoke.sh M1
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/../config/env.sh"

FILTER="${1:-}"
PASS=0; FAIL=0; SKIP=0
RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; DIM=$'\033[2m'; OFF=$'\033[0m'

ok()   { PASS=$((PASS+1)); echo "  ${GRN}PASS${OFF} $1"; }
bad()  { FAIL=$((FAIL+1)); echo "  ${RED}FAIL${OFF} $1"; [ -n "${2:-}" ] && echo "       ${DIM}$2${OFF}"; }
skip() { SKIP=$((SKIP+1)); echo "  ${YEL}SKIP${OFF} $1 ${DIM}($2)${OFF}"; }

want() { [ -z "$FILTER" ] || [[ "$1" == "$FILTER"* ]]; }

# GET/POST helper: prints "<status>\n<body>"
req() {
  local verb="$1" url="$2"; shift 2
  curl -sS -X "$verb" -o /tmp/airlock.body -w '%{http_code}' "$url" "$@" 2>/tmp/airlock.err
}
body() { cat /tmp/airlock.body 2>/dev/null; }

status_is() { # desc expected actual
  if [ "$3" = "$2" ]; then ok "$1"; else bad "$1" "expected HTTP $2, got $3 -- $(body | head -c 200)"; fi
}

echo "Gateway: $APIGEE_BASE   org=$APIGEE_ORG env=$APIGEE_ENV"
echo

# ---------------------------------------------------------------- M0
if want M0; then
echo "M0 -- provisioning & routing"
  envs="$(apigeecli environments list -o "$APIGEE_ORG" -t "$(token)" --no-warnings 2>/dev/null)"
  if echo "$envs" | grep -q "\"$APIGEE_ENV\""; then ok "env '$APIGEE_ENV' exists"; else bad "env '$APIGEE_ENV' exists" "$envs"; fi

  code="$(req GET "$APIGEE_BASE/" --max-time 20)"
  hdrs="$(curl -sS -o /dev/null -D - --max-time 20 "$APIGEE_BASE/" 2>/dev/null)"
  if [ -n "$code" ] && [ "$code" != "000" ]; then
    ok "gateway reachable over TLS (HTTP $code)"
  else
    bad "gateway reachable over TLS" "$(cat /tmp/airlock.err 2>/dev/null | head -c 200)"
  fi
echo
fi

# ---------------------------------------------------------------- M1
if want M1; then
echo "M1 -- weather-v1 passthrough + API key"
  FC="$APIGEE_BASE/weather/v1/forecast?latitude=43.7&longitude=-79.4&current=temperature_2m"

  status_is "no API key -> 401"  401 "$(req GET "$FC" --max-time 20)"
  status_is "bad API key -> 401" 401 "$(req GET "$FC" -H "x-api-key: not-a-real-key" --max-time 20)"

  if [ -n "${AGENT_READER_KEY:-}" ]; then
    code="$(req GET "$FC" -H "x-api-key: $AGENT_READER_KEY" --max-time 20)"
    if [ "$code" = "200" ] && body | grep -q '"temperature_2m"'; then
      ok "reader key -> 200 with current.temperature_2m"
    else
      bad "reader key -> 200 with current.temperature_2m" "HTTP $code -- $(body | head -c 200)"
    fi
  else
    skip "reader key -> 200" "AGENT_READER_KEY unset; run scripts/provision.sh"
  fi
echo
fi

# ---------------------------------------------------------------- M2
if want M2; then
echo "M2 -- scope enforcement across two identities"
  FC="$APIGEE_BASE/weather/v1/forecast?latitude=43.7&longitude=-79.4&current=temperature_2m"
  AR="$APIGEE_BASE/weather/v1/archive?latitude=43.7&longitude=-79.4&start_date=2024-01-01&end_date=2024-01-02&daily=temperature_2m_max"

  if [ -n "${AGENT_READER_KEY:-}" ] && [ -n "${AGENT_OPERATOR_KEY:-}" ]; then
    status_is "reader   /forecast -> 200" 200 "$(req GET "$FC" -H "x-api-key: $AGENT_READER_KEY"   --max-time 20)"
    status_is "reader   /archive  -> 403" 403 "$(req GET "$AR" -H "x-api-key: $AGENT_READER_KEY"   --max-time 20)"

    code="$(req GET "$AR" -H "x-api-key: $AGENT_OPERATOR_KEY" --max-time 20)"
    if [ "$code" = "200" ] && body | grep -q '"temperature_2m_max"'; then
      ok "operator /archive  -> 200 with daily.temperature_2m_max"
    else
      bad "operator /archive  -> 200 with daily.temperature_2m_max" "HTTP $code -- $(body | head -c 200)"
    fi
    status_is "operator /forecast -> 200" 200 "$(req GET "$FC" -H "x-api-key: $AGENT_OPERATOR_KEY" --max-time 20)"
  else
    skip "scope tests" "agent keys unset; run scripts/provision.sh"
  fi
echo
fi

# ---------------------------------------------------------------- M3
if want M3; then
echo "M3 -- traffic protection & fault sanitization"
  FC="$APIGEE_BASE/weather/v1/forecast?latitude=43.7&longitude=-79.4&current=temperature_2m"

  # Every error must use the gateway's own {"error","message"} shape.
  shape_is() { # desc expected-code expected-error url [header]
    local desc="$1" want_code="$2" want_err="$3" url="$4" hdr="${5:-}"
    local code
    if [ -n "$hdr" ]; then code="$(req GET "$url" -H "$hdr" --max-time 25)"
    else code="$(req GET "$url" --max-time 25)"; fi
    local b; b="$(body)"
    if [ "$code" = "$want_code" ] && echo "$b" | grep -q "\"error\":\"$want_err\""; then
      ok "$desc"
    else
      bad "$desc" "HTTP $code -- $(echo "$b" | head -c 200)"
    fi
  }

  shape_is "no key      -> 401 unauthorized" 401 unauthorized "$FC"
  shape_is "bad key     -> 401 unauthorized" 401 unauthorized "$FC" "x-api-key: nope"
  if [ -n "${AGENT_READER_KEY:-}" ]; then
    shape_is "off-scope   -> 403 forbidden"  403 forbidden \
      "$APIGEE_BASE/weather/v1/archive?latitude=43.7" "x-api-key: $AGENT_READER_KEY"

    # Fault bodies must not name Apigee, policies, or internal steps.
    req GET "$FC" -H "x-api-key: nope" --max-time 25 >/dev/null
    if body | grep -qiE 'apigee|policy|steps\.|stacktrace'; then
      bad "fault body free of Apigee internals" "$(body | head -c 200)"
    else
      ok "fault body free of Apigee internals"
    fi
  else
    skip "fault-shape tests" "AGENT_READER_KEY unset"
  fi

  if python -m pytest -q -k traffic >/tmp/airlock.pytest 2>&1; then
    ok "pytest -k traffic ($(grep -oE '[0-9]+ passed' /tmp/airlock.pytest | head -1))"
  else
    bad "pytest -k traffic" "$(tail -5 /tmp/airlock.pytest)"
  fi
echo
fi

echo "-------------------------------------------"
echo "passed=$PASS failed=$FAIL skipped=$SKIP"
[ "$FAIL" -eq 0 ] || exit 1
