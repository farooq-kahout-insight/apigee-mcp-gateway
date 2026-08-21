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

echo "-------------------------------------------"
echo "passed=$PASS failed=$FAIL skipped=$SKIP"
[ "$FAIL" -eq 0 ] || exit 1
