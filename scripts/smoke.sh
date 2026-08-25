#!/usr/bin/env bash
# Acceptance / regression suite. Every milestone appends tests; old ones must keep passing.
# Usage: scripts/smoke.sh [milestone ...]   e.g. scripts/smoke.sh M9 M10
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$HERE/../config/env.sh"

FILTERS=()
[ $# -gt 0 ] && FILTERS=("$@")
PASS=0; FAIL=0; SKIP=0
RED=$'\033[31m'; GRN=$'\033[32m'; YEL=$'\033[33m'; DIM=$'\033[2m'; OFF=$'\033[0m'

ok()   { PASS=$((PASS+1)); echo "  ${GRN}PASS${OFF} $1"; }
bad()  { FAIL=$((FAIL+1)); echo "  ${RED}FAIL${OFF} $1"; [ -n "${2:-}" ] && echo "       ${DIM}$2${OFF}"; }
skip() { SKIP=$((SKIP+1)); echo "  ${YEL}SKIP${OFF} $1 ${DIM}($2)${OFF}"; }

# Exact match, and every argument is honoured. This used to be a prefix test on
# $1 alone, which was harmless while the milestones were M0..M7 and quietly wrong
# afterwards: `smoke.sh M1` also ran M10 and M11, and `smoke.sh M9 M10` ran M9 and
# silently dropped M10 -- reporting a clean pass for a milestone it never touched.
# A filter that runs the wrong tests is worse than one that runs none.
want() {
  [ ${#FILTERS[@]} -eq 0 ] && return 0
  local f
  for f in "${FILTERS[@]}"; do [ "$1" = "$f" ] && return 0; done
  return 1
}

# GET/POST helper: prints "<status>\n<body>"
req() {
  local verb="$1" url="$2"; shift 2
  curl -sS -X "$verb" -o /tmp/airlock.body -w '%{http_code}' "$url" "$@" 2>/tmp/airlock.err
}
body() { cat /tmp/airlock.body 2>/dev/null; }

# Same as req, for the handful of calls that actually spend tokens. Free-tier
# model providers rate-limit per minute, so a 429 there says nothing about this
# gateway and would make every model-dependent test below flaky. Only an
# *upstream* 429 is retried: that one arrives as "rate_limited" from
# AM-Upstream-RateLimited, whereas the gateway's own Q-LLM-Quota refusal is
# shaped "quota_exceeded" and must never be papered over -- retrying that would
# turn the quota test green by exhausting it more slowly.
#
# The retry budget is small on purpose. Every retry is itself a request through
# the gateway and counts against Q-LLM-Quota, so a generous loop converts the
# provider's rate limit into this gateway's quota exhaustion and takes the rest
# of the milestone down with it. That is not hypothetical: a five-try version of
# this helper spent both its budgets waiting out a busy free tier, and the three
# tests after it failed on a quota its own retries had consumed. Two tries buys
# through a single unlucky minute, and llm_answered below handles the case where
# the tier is busy for longer than that.
req_llm() {
  local tries="${LLM_RETRIES:-2}" code=""
  while [ "$tries" -gt 0 ]; do
    code="$(req "$@")"
    [ "$code" = "429" ] || { echo "$code"; return; }
    grep -q 'rate_limited' /tmp/airlock.body 2>/dev/null || { echo "$code"; return; }
    tries=$((tries - 1))
    [ "$tries" -gt 0 ] && sleep 20
  done
  echo "$code"
}

# Did the gateway ever get to answer the question the test was asking?
#
# Two different 429s reach the model tests and neither is a verdict on this
# gateway. "rate_limited" is the free tier refusing to serve anybody just now;
# "quota_exceeded" is the gateway's own hourly model budget for this key, which
# a second run of the suite inside the same hour will exhaust by itself. Calling
# either one a failure reports "the gateway is broken" when the true finding is
# "there was no completion to inspect", so both skip -- loudly, naming which --
# and only a real answer is asserted against.
#
# This does not leave the quota policy untested. AIRLOCK_QUOTA_TEST exists to
# prove Q-LLM-Quota fires, and it deliberately uses bare req so that no amount of
# tolerance here can turn that test green.
llm_answered() { # desc code -> 0 to assert, 1 to skip
  [ "$2" = "429" ] || return 0
  if grep -q 'quota_exceeded' /tmp/airlock.body 2>/dev/null; then
    skip "$1" "this key's hourly model budget is spent; it resets on the hour"
  else
    skip "$1" "the free tier is rate-limiting; nothing here is the gateway's doing"
  fi
  return 1
}

status_is() { # desc expected actual
  if [ "$3" = "$2" ]; then ok "$1"; else bad "$1" "expected HTTP $2, got $3 -- $(body | head -c 200)"; fi
}

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

echo "Gateway: $APIGEE_BASE   org=$APIGEE_ORG env=$APIGEE_ENV"
echo

# ---------------------------------------------------------------- M0
if want M0; then
echo "M0 -- provisioning & routing"
  # Every bundle must parse before anything is uploaded. This is cheap and it is
  # here because it caught a whole proxy at once: XML forbids "--" inside a
  # comment, and prose written with double hyphens for dashes produces a bundle
  # that is invalid in a way no policy-level review notices. The failure it
  # prevents is an import rejected by the control plane with a line number and
  # no file name.
  if command -v python >/dev/null 2>&1; then
    malformed=""
    for f in $(find "$HERE/.." -path "$HERE/../node_modules" -prune -o -name '*.xml' -print); do
      python -c "import sys,xml.dom.minidom as m; m.parse(sys.argv[1])" "$f" 2>/dev/null \
        || malformed="$malformed $(basename "$f")"
    done
    if [ -z "$malformed" ]; then ok "every proxy and shared-flow XML is well-formed"
    else bad "every proxy and shared-flow XML is well-formed" "malformed:$malformed"; fi
  else
    skip "every proxy and shared-flow XML is well-formed" "python not installed"
  fi

  # The other deploy-time-only failure class, and the more expensive one to
  # diagnose: the Apigee expression parser reads "x is not null" as a NOT
  # applied to null, and rejects the whole bundle with OperandsShouldBeLogical
  # -- naming no file, no line and no policy. The spelling that parses is
  # "!= null". Plain "is null" is valid and used throughout, so this looks only
  # for the negated form, and only inside a Condition.
  badcond="$(grep -rl 'is not null' "$HERE/../proxies" "$HERE/../sharedflows" \
             --include='*.xml' 2>/dev/null | while read -r f; do
               grep -q '<Condition>[^<]*is not null' "$f" && basename "$f"; done)"
  if [ -z "$badcond" ]; then ok "no condition uses the unparseable 'is not null'"
  else bad "no condition uses the unparseable 'is not null'" "$(echo $badcond)"; fi

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

# ---------------------------------------------------------------- M4
if want M4; then
echo "M4 -- payload threat protection & response redaction"
  # The scrubber's pure functions are tested under Node; the gateway tests below
  # prove the same file behaves identically inside Apigee's Rhino engine.
  if command -v node >/dev/null 2>&1; then
    if node "$HERE/../tests/test_redact.js" >/tmp/airlock.node 2>&1; then
      ok "redact.js unit tests ($(grep -c '^  ok' /tmp/airlock.node) cases)"
    else
      bad "redact.js unit tests" "$(grep '^  FAIL' -A1 /tmp/airlock.node | head -6)"
    fi
  else
    skip "redact.js unit tests" "node not installed"
  fi

  Q="$APIGEE_BASE/weather/v1/forecast?latitude=43.7&longitude=-79.4"
  if [ -n "${AGENT_READER_KEY:-}" ]; then
    RK="x-api-key: $AGENT_READER_KEY"
    # Injection strings must be rejected by the gateway itself. Asserting on the
    # gateway's own body matters: an upstream that happens to 400 on a malformed
    # parameter would otherwise mask a policy that never fired.
    shape_is "sqli  '%20OR%201=1 -> 400" 400 bad_request "$Q&q='%20OR%201=1"     "$RK"
    shape_is "sqli  1+OR+1=1     -> 400" 400 bad_request "$Q&q=1+OR+1=1"         "$RK"
    shape_is "sqli  union select -> 400" 400 bad_request "$Q&q=union%20select"   "$RK"
    shape_is "xss   <script>     -> 400" 400 bad_request "$Q&q=%3Cscript%3E"     "$RK"
    shape_is "xss   javascript:  -> 400" 400 bad_request "$Q&q=javascript%3Aevil" "$RK"

    code="$(req GET "$Q&current=temperature_2m" -H "$RK" --max-time 25)"
    if [ "$code" = "200" ]; then ok "clean query still passes -> 200"
    else bad "clean query still passes -> 200" "HTTP $code -- $(body | head -c 200)"; fi
  else
    skip "injection tests" "AGENT_READER_KEY unset"
  fi

  if [ -n "${AGENT_OPERATOR_KEY:-}" ]; then
    OK_H="x-api-key: $AGENT_OPERATOR_KEY"
    ST="$APIGEE_BASE/weather/v1/selftest"

    # A 50-level-deep body must be refused before any parser downstream sees it.
    python - >/tmp/airlock.deep <<'PYD'
import io
n = 50
io.open(1, "w", encoding="utf-8", newline="\n", closefd=False).write(
    '{"a":' * n + '1' + '}' * n)
PYD
    code="$(req POST "$ST" -H "$OK_H" -H 'Content-Type: application/json' \
            --data-binary @/tmp/airlock.deep --max-time 25)"
    if [ "$code" = "400" ] && body | grep -q '"error":"bad_request"'; then
      ok "50-deep JSON body -> 400 bad_request"
    else
      bad "50-deep JSON body -> 400 bad_request" "HTTP $code -- $(body | head -c 200)"
    fi

    # Control: the same endpoint with a shallow body must succeed, proving the
    # 400 above came from the depth limit and not from the flow being broken.
    code="$(req POST "$ST" -H "$OK_H" -H 'Content-Type: application/json' \
            --data '{"a":{"b":1}}' --max-time 25)"
    status_is "shallow JSON body (control) -> 200" 200 "$code"

    # Redaction, end to end: the selftest flow returns a canned payload carrying
    # every credential shape plus two emails.
    code="$(req GET "$ST" -H "$OK_H" --max-time 25)"
    b="$(body)"
    if [ "$code" != "200" ]; then
      bad "selftest payload reachable" "HTTP $code -- $(echo "$b" | head -c 200)"
    else
      leaked=""
      for k in access_token api_key refresh_token password abc123 sk-not-real rt-fake hunter2; do
        echo "$b" | grep -q -- "$k" && leaked="$leaked $k"
      done
      if [ -z "$leaked" ]; then ok "credential keys and values stripped from response"
      else bad "credential keys and values stripped from response" "leaked:$leaked"; fi

      if echo "$b" | grep -q 'a\*\*\*@example\.com' && echo "$b" | grep -q 'b\*\*\*@example\.org'; then
        ok "emails masked in structured and free-text fields"
      else
        bad "emails masked in structured and free-text fields" "$(echo "$b" | head -c 200)"
      fi

      if echo "$b" | grep -qE '[a-z]+@example\.(com|org)'; then
        bad "no unmasked address survives" "$(echo "$b" | head -c 200)"
      else
        ok "no unmasked address survives"
      fi

      # Redaction must not destroy the surrounding structure.
      if echo "$b" | grep -q '"ok":true' && echo "$b" | grep -q '"id":7'; then
        ok "non-sensitive fields preserved through redaction"
      else
        bad "non-sensitive fields preserved through redaction" "$(echo "$b" | head -c 200)"
      fi
    fi
  else
    skip "redaction & depth tests" "AGENT_OPERATOR_KEY unset"
  fi
echo
fi

# ---------------------------------------------------------------- M5
if want M5; then
echo "M5 -- github-v1: KVM credential injection & repo allowlist"
  if command -v node >/dev/null 2>&1; then
    if node "$HERE/../tests/test_github_issue.js" >/tmp/airlock.node 2>&1; then
      ok "github_issue.js unit tests ($(grep -c '^  ok' /tmp/airlock.node) cases)"
    else
      bad "github_issue.js unit tests" "$(grep '^  FAIL' -A1 /tmp/airlock.node | head -6)"
    fi
  else
    skip "github_issue.js unit tests" "node not installed"
  fi

  GH="$APIGEE_BASE/github/v1"
  # A repository that is deliberately not the allowlisted one. Real and public,
  # so a 403 proves the allowlist fired rather than the request simply 404ing.
  OTHER="octocat/Hello-World"

  # ---- static checks: the PAT must not be reachable from this repository ----
  # Tracked files only: this is the "someone pasted it in to debug" regression.
  if git -C "$HERE/.." grep -InE 'gh[pousr]_[A-Za-z0-9]{16,}|github_pat_[A-Za-z0-9_]{20,}' -- . >/tmp/airlock.pat 2>/dev/null; then
    bad "no GitHub token literal in tracked files" "$(head -c 200 /tmp/airlock.pat)"
  else
    ok "no GitHub token literal in tracked files"
  fi

  if grep -qE '(^|/)\.env$' "$HERE/../.gitignore" 2>/dev/null; then
    ok ".env is gitignored"
  else
    bad ".env is gitignored" "the file that holds local keys is not excluded from git"
  fi

  if [ -n "${GITHUB_PAT:-}" ]; then
    # The live value, not just its shape. .env is excluded: it is gitignored and
    # is the sanctioned place for a local operator to keep it. Everything else --
    # scripts, bundles, the synced resources/jsc copies -- must be clean.
    if grep -rIF -- "$GITHUB_PAT" "$HERE/.." --exclude-dir=.git --exclude=.env >/dev/null 2>&1; then
      bad "live PAT absent from committable files" "found outside .env"
    else
      ok "live PAT absent from committable files"
    fi
  else
    skip "live PAT absent from committable files" "GITHUB_PAT unset"
  fi

  if [ -n "${AGENT_READER_KEY:-}" ] && [ -n "${AGENT_OPERATOR_KEY:-}" ]; then
    RK="x-api-key: $AGENT_READER_KEY"; OKH="x-api-key: $AGENT_OPERATOR_KEY"

    status_is "github: no API key -> 401" 401 "$(req GET "$GH/repos/$OTHER/issues" --max-time 25)"

    # Scope: the reader product grants GET only. This 403 comes from the API
    # Product, before any repository check or KVM lookup runs.
    code="$(req POST "$GH/repos/$OTHER/issues" -H "$RK" -H 'Content-Type: application/json' \
            --data '{"title":"should not be created"}' --max-time 25)"
    if [ "$code" = "403" ] && body | grep -q 'not scoped'; then
      ok "reader cannot POST an issue -> 403 scope"
    else
      bad "reader cannot POST an issue -> 403 scope" "HTTP $code -- $(body | head -c 200)"
    fi

    # Blast radius. Only /repos/{owner}/{repo}/issues appears in either product,
    # so nothing else on api.github.com is reachable through this gateway even
    # for the operator -- the stored PAT is far more privileged than the single
    # endpoint agents are allowed to spend it on.
    for path in "/repos/$OTHER/issues/1/comments" "/repos/$OTHER/pulls" "/user/repos" "/user"; do
      code="$(req GET "$GH$path" -H "$OKH" --max-time 25)"
      if [ "$code" = "403" ] || [ "$code" = "404" ]; then
        ok "operator blocked from $path (HTTP $code)"
      else
        bad "operator blocked from $path" "HTTP $code -- $(body | head -c 200)"
      fi
    done

    # Allowlist: any repo other than the configured one is refused, and the
    # refusal does not echo back which repository was asked for.
    code="$(req GET "$GH/repos/$OTHER/issues" -H "$OKH" --max-time 25)"
    b="$(body)"
    if [ "$code" = "403" ] && echo "$b" | grep -q 'not authorized for that repository'; then
      if echo "$b" | grep -qi 'octocat'; then
        bad "non-allowlisted repo -> 403 without echoing the target" "body echoed the repo"
      else
        ok "non-allowlisted repo -> 403 without echoing the target"
      fi
    else
      bad "non-allowlisted repo -> 403 without echoing the target" "HTTP $code -- $(echo "$b" | head -c 200)"
    fi

    # What .env says is not evidence about the gateway. The allowlist the tests
    # below exercise lives in a KVM, and until provision.sh has been run with the
    # PAT and the repository exported, that KVM is empty -- a variable somebody
    # set by hand proves only that it was written down somewhere. Run without
    # this check, those tests fail against a gateway that is behaving correctly,
    # and they fail with a refusal that reads like a broken credential.
    ALLOW_PROVISIONED=""
    if [ -n "${GITHUB_ALLOWED_REPO:-}" ] && command -v gcloud >/dev/null 2>&1; then
      if curl -sS -H "Authorization: Bearer $(token)"            "https://apigee.googleapis.com/v1/organizations/$APIGEE_ORG/environments/$APIGEE_ENV/keyvaluemaps/gateway-config/entries"            2>/dev/null | grep -q '"github_allowed_repo"'; then
        ALLOW_PROVISIONED=yes
      fi
    fi

    if [ -n "${GITHUB_ALLOWED_REPO:-}" ] && [ -n "$ALLOW_PROVISIONED" ]; then
      ALLOW="$GITHUB_ALLOWED_REPO"

      # The headline test for this milestone: the caller holds no GitHub
      # credential, yet an authenticated GitHub call succeeds. A 401 here would
      # mean the PAT is missing, expired, or lacks the repo scope.
      code="$(req GET "$GH/repos/$ALLOW/issues" -H "$RK" --max-time 30)"
      b="$(body)"
      case "$code" in
        200)     ok "reader lists issues on the allowlisted repo -> 200 (PAT injected by gateway)" ;;
        401|403) bad "reader lists issues on the allowlisted repo -> 200" "HTTP $code: PAT missing, expired, or lacking repo scope -- $(echo "$b" | head -c 200)" ;;
        *)       bad "reader lists issues on the allowlisted repo -> 200" "HTTP $code -- $(echo "$b" | head -c 200)" ;;
      esac

      # The upstream response must not carry credential material back out.
      if echo "$b" | grep -qiE 'ghp_|github_pat_|"authorization"'; then
        bad "no credential material in the GitHub response" "$(echo "$b" | head -c 160)"
      else
        ok "no credential material in the GitHub response"
      fi

      # Payload validation runs before the upstream call, so these cost nothing
      # on GitHub's side and create nothing.
      for bad_body in '{"body":"no title"}' '{"title":"   "}' 'not json at all' '["array"]'; do
        code="$(req POST "$GH/repos/$ALLOW/issues" -H "$OKH" -H 'Content-Type: application/json' \
                --data "$bad_body" --max-time 25)"
        if [ "$code" = "400" ] && body | grep -q '"error":"bad_request"'; then
          ok "malformed issue payload rejected before upstream: $(echo "$bad_body" | head -c 22)"
        else
          bad "malformed issue payload rejected before upstream: $(echo "$bad_body" | head -c 22)" "HTTP $code -- $(body | head -c 200)"
        fi
      done

      # Creating an issue is a real, visible side effect on someone's repository,
      # so it is opt-in rather than part of the default regression run.
      if [ "${AIRLOCK_WRITE_TESTS:-}" = "1" ]; then
        stamp="$(date -u +%Y%m%dT%H%M%SZ)"
        # The extra fields are the point of the test: the gateway rebuilds the
        # payload from an allowlist, so assignees, labels and milestone must not
        # reach GitHub even though GitHub itself would happily accept them.
        payload="$(printf '{"title":"airlock smoke %s","body":"created by scripts/smoke.sh","assignees":["octocat"],"labels":["bug"],"milestone":1}' "$stamp")"
        code="$(req POST "$GH/repos/$ALLOW/issues" -H "$OKH" -H 'Content-Type: application/json' \
                --data "$payload" --max-time 30)"
        b="$(body)"
        if [ "$code" = "201" ]; then
          ok "operator creates an issue -> 201"
          if echo "$b" | grep -q '"assignees":\[\]'; then
            ok "assignees stripped from the created issue"
          else
            bad "assignees stripped from the created issue" "$(echo "$b" | head -c 300)"
          fi
          if echo "$b" | grep -q '"labels":\[\]' && echo "$b" | grep -q '"milestone":null'; then
            ok "labels and milestone stripped from the created issue"
          else
            bad "labels and milestone stripped from the created issue" "$(echo "$b" | head -c 300)"
          fi
        else
          bad "operator creates an issue -> 201" "HTTP $code -- $(echo "$b" | head -c 250)"
        fi
      else
        skip "issue creation tests" "set AIRLOCK_WRITE_TESTS=1 -- they create real issues in $ALLOW"
      fi
    elif [ -n "${GITHUB_ALLOWED_REPO:-}" ]; then
      # The allowlist has not been provisioned. That is a legitimate state to be
      # in, but it is worth one assertion on the way past, because it is the only
      # configuration in which this particular failure is observable: an absent
      # allowlist must deny. A missing KVM entry leaves gh.allowed_repo null, and
      # a null comparison that came out "equal" would hand the stored PAT every
      # repository on GitHub -- the exact blast radius this milestone exists to
      # bound. Cheap to check, catastrophic to get wrong.
      code="$(req GET "$GH/repos/$GITHUB_ALLOWED_REPO/issues" -H "$RK" --max-time 25)"
      if [ "$code" = "403" ]; then
        ok "an unprovisioned allowlist closes github rather than opening it"
      else
        bad "an unprovisioned allowlist closes github rather than opening it"             "HTTP $code -- a missing allowlist admitted a request"
      fi
      skip "allowlisted-repo tests" "gateway-config/github_allowed_repo is not provisioned -- run: GITHUB_PAT=... GITHUB_ALLOWED_REPO=owner/repo bash scripts/provision.sh"
    else
      skip "allowlisted-repo tests" "GITHUB_ALLOWED_REPO unset; see scripts/provision.sh"
    fi
  else
    skip "github-v1 gateway tests" "agent keys unset; run scripts/provision.sh"
  fi
echo
fi

# ---------------------------------------------------------------- M6
if want M6; then
echo "M6 -- MCP server: the agent's only route to a backend"
  MCPDIR="$HERE/../mcp-server"

  # Static: no tool may take a URL, a host, or a header from its caller. This is
  # what stops a prompt injection turning the server into an open proxy -- the
  # base URL is fixed at startup and every tool builds its path from a fixed
  # literal, so it is worth failing the build if someone adds a parameter that
  # would reopen that door.
  if grep -nE '^\s*(url|base_url|host|endpoint|headers|target)\s*:' "$MCPDIR/server.py" \
       | grep -v '^\s*#' >/tmp/airlock.mcp 2>/dev/null; then
    bad "no tool takes a url/host/header argument" "$(head -c 200 /tmp/airlock.mcp)"
  else
    ok "no tool takes a url/host/header argument"
  fi

  # The server must not know how to talk to a backend directly.
  if grep -nE 'api\.github\.com|api\.open-meteo\.com|homeassistant' "$MCPDIR/server.py" >/dev/null 2>&1; then
    bad "no direct backend hostname in server.py" "a backend host appears in the source"
  else
    ok "no direct backend hostname in server.py"
  fi

  if [ -n "${AGENT_READER_KEY:-}" ] && grep -q "$AGENT_READER_KEY" "$MCPDIR/server.py" 2>/dev/null; then
    bad "no agent key baked into server.py" "the key is in the source, not the environment"
  else
    ok "no agent key baked into server.py"
  fi

  # End to end: the tests below spawn the real server over stdio and speak MCP
  # to it. They live in the server's own virtualenv because the mcp client
  # library is a dependency of the server, not of this repository.
  if command -v uv >/dev/null 2>&1; then
    if (cd "$MCPDIR" && uv run --with pytest --with requests \
          python -m pytest ../tests/test_mcp_server.py -q) >/tmp/airlock.mcpt 2>&1; then
      ok "mcp stdio end-to-end tests ($(grep -oE '[0-9]+ passed' /tmp/airlock.mcpt | head -1))"
    else
      bad "mcp stdio end-to-end tests" "$(grep -E '^(FAILED|E  |assert)' /tmp/airlock.mcpt | head -6)"
    fi
  else
    skip "mcp stdio end-to-end tests" "uv not installed"
  fi
echo
fi

# ---------------------------------------------------------------- M7
if want M7; then
echo "M7 -- audit trail, metric and alert"
  AUDIT_LOG="${AUDIT_LOG_NAME:-agent-airlock-audit}"
  AUDIT_FILTER="logName=\"projects/$APIGEE_ORG/logs/$AUDIT_LOG\""

  # Unit: the record builder, run against the same shared/js file that deploy.sh
  # copies into the bundle, so a change to the schema cannot pass here and fail
  # in the gateway.
  if command -v node >/dev/null 2>&1; then
    if node "$HERE/../tests/test_audit.js" >/tmp/airlock.audit 2>&1; then
      ok "audit record builder unit tests ($(grep -c '  ok ' /tmp/airlock.audit) assertions)"
    else
      bad "audit record builder unit tests" "$(tail -6 /tmp/airlock.audit)"
    fi
  else
    skip "audit record builder unit tests" "node not installed"
  fi

  # Structural, and worth its own test: PostClientFlow runs MessageLogging
  # policies and nothing else. A JavaScript step placed there reports success
  # and silently does nothing, which is how this gateway spent a day logging
  # empty records. The shape below is the thing that keeps that from recurring.
  if python "$HERE/../tests/check_audit_wiring.py" >/tmp/airlock.wire 2>&1; then
    ok "audit is built on the response and fault paths, written in PostClientFlow"
  else
    bad "audit is built on the response and fault paths, written in PostClientFlow" \
        "$(head -6 /tmp/airlock.wire)"
  fi

  if [ -z "${AGENT_READER_KEY:-}" ]; then
    skip "every call reaches Cloud Logging with its agent identity" "no AGENT_READER_KEY; run scripts/provision.sh"
    skip "a refused call is audited as denied" "no AGENT_READER_KEY; run scripts/provision.sh"
    skip "a refusal at the product scope still names the agent" "no AGENT_READER_KEY; run scripts/provision.sh"
    skip "the audit carries no credential" "no AGENT_READER_KEY; run scripts/provision.sh"
    skip "the recorded caller address survives the load balancer" "no AGENT_READER_KEY; run scripts/provision.sh"
  elif ! command -v gcloud >/dev/null 2>&1; then
    skip "every call reaches Cloud Logging with its agent identity" "gcloud not installed"
    skip "a refused call is audited as denied" "gcloud not installed"
    skip "a refusal at the product scope still names the agent" "gcloud not installed"
    skip "the audit carries no credential" "gcloud not installed"
    skip "the recorded caller address survives the load balancer" "gcloud not installed"
  else
    # Two calls with opposite fates: one the reader is entitled to make, and one
    # the API Product forbids. The pair is the point -- an audit that captures
    # only the calls that succeeded answers the wrong question.
    SINCE="$(date -u -d '-30 seconds' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%SZ)"
    req GET "$APIGEE_BASE/weather/v1/forecast?latitude=43.7&longitude=-79.4&current=temperature_2m" \
      -H "x-api-key: $AGENT_READER_KEY" --max-time 25 >/dev/null
    req GET "$APIGEE_BASE/weather/v1/archive?latitude=43.7&longitude=-79.4&start_date=2024-01-01&end_date=2024-01-02" \
      -H "x-api-key: $AGENT_READER_KEY" --max-time 25 >/dev/null

    # Cloud Logging ingestion is asynchronous and the write happens after the
    # response has gone out, so a poll is correct here rather than a fixed sleep.
    # The assertions match on content rather than on count, so a stray record
    # from other traffic cannot turn this green or red by accident.
    ENTRIES='[]'
    for _ in 1 2 3 4 5 6 7 8 9 10 11 12; do
      ENTRIES="$(gcloud logging read "$AUDIT_FILTER AND timestamp>=\"$SINCE\"" \
        --project "$APIGEE_ORG" --limit 50 --order asc --format json 2>/dev/null)"
      [ -n "$ENTRIES" ] || ENTRIES='[]'
      printf '%s' "$ENTRIES" >/tmp/airlock.entries
      # Wait for the two records this block is about, not for any two records.
      # Counting was enough until the suite grew long enough for Apigee to ship
      # a batch of older audit records into the window: the poll saw two
      # entries, both of them GitHub refusals from M5, and broke out before
      # either weather call had been written. That turned an ingestion race into
      # two red tests whose messages named a caller-address regression and a
      # missing forecast, neither of which had happened. The break condition is
      # now the assertion itself, so the poll ends when the evidence is there
      # and only otherwise runs out its budget.
      if python "$HERE/../tests/check_audit_entries.py" served </tmp/airlock.entries >/dev/null 2>&1 \
         && python "$HERE/../tests/check_audit_entries.py" refused </tmp/airlock.entries >/dev/null 2>&1; then
        break
      fi
      sleep 10
    done

    audit_q() { python "$HERE/../tests/check_audit_entries.py" "$1" </tmp/airlock.entries; }

    if audit_q served >/tmp/airlock.aq 2>&1; then
      ok "every call reaches Cloud Logging with its agent identity"
    else
      bad "every call reaches Cloud Logging with its agent identity" "$(head -4 /tmp/airlock.aq)"
    fi
    if audit_q refused >/tmp/airlock.aq 2>&1; then
      ok "a refused call is audited as denied"
    else
      bad "a refused call is audited as denied" "$(head -4 /tmp/airlock.aq)"
    fi
    if audit_q named >/tmp/airlock.aq 2>&1; then
      ok "a refusal at the product scope still names the agent"
    else
      bad "a refusal at the product scope still names the agent" "$(head -4 /tmp/airlock.aq)"
    fi
    if audit_q clean >/tmp/airlock.aq 2>&1; then
      ok "the audit carries no credential"
    else
      bad "the audit carries no credential" "$(head -4 /tmp/airlock.aq)"
    fi
    if audit_q caller >/tmp/airlock.aq 2>&1; then
      ok "the recorded caller address survives the load balancer"
    else
      bad "the recorded caller address survives the load balancer" "$(head -4 /tmp/airlock.aq)"
    fi
  fi

  # Static counterpart to the live check above. The snapshot only covers an
  # unauthenticated request if it is taken before the key is verified, and the
  # only thing keeping it there is that nobody reorders the shared flow.
  SFDEF="$HERE/../sharedflows/sf-inbound-security/sharedflowbundle/sharedflows/default.xml"
  if [ "$(grep -oE '<Name>[A-Za-z-]+</Name>' "$SFDEF" | head -1)" = "<Name>AM-Capture-Caller</Name>" ]; then
    ok "the caller address is captured before the key is checked"
  else
    bad "the caller address is captured before the key is checked"         "first step of sf-inbound-security is $(grep -oE '<Name>[A-Za-z-]+</Name>' "$SFDEF" | head -1)"
  fi

  # The metric and the alert are the difference between a log nobody reads and
  # a control that tells a human when an agent starts behaving like a bot.
  METRIC="${AUDIT_METRIC:-airlock_github_writes}"
  if gcloud logging metrics describe "$METRIC" --project "$APIGEE_ORG" --format json >/tmp/airlock.metric 2>&1; then
    if grep -q 'github.issues.create' /tmp/airlock.metric; then
      ok "log-based metric '$METRIC' counts github write attempts"
    else
      bad "log-based metric '$METRIC' counts github write attempts" "filter does not mention github.issues.create"
    fi
  else
    bad "log-based metric '$METRIC' counts github write attempts" "not found -- run scripts/monitoring.sh"
  fi

  if gcloud alpha monitoring policies list --project "$APIGEE_ORG" --format json >/tmp/airlock.pol 2>/dev/null \
     && grep -q 'Agent Airlock' /tmp/airlock.pol; then
    if python "$HERE/../tests/check_alert_policy.py" </tmp/airlock.pol >/tmp/airlock.polq 2>&1; then
      ok "alert policy fires above 20 write attempts per agent per hour"
    else
      bad "alert policy fires above 20 write attempts per agent per hour" "$(head -4 /tmp/airlock.polq)"
    fi
  else
    skip "alert policy fires above 20 write attempts per agent per hour" "policy not found -- run scripts/monitoring.sh"
  fi

  # The three analytics views. Two things are checked, and the second is the one
  # that matters: that the report exists, and that the metric-and-dimension pair
  # it asks for actually returns rows. The custom-report API does not validate
  # metric names -- a report selecting "p95_total_response_time" is created
  # happily and then renders nothing at all -- so "it was created" is no evidence
  # whatsoever. Querying the stats API with the same selectors is.
  if command -v curl >/dev/null 2>&1 && TOK="$(token)" && [ -n "$TOK" ]; then
    curl -sS -H "Authorization: Bearer $TOK" \
      "https://apigee.googleapis.com/v1/organizations/$APIGEE_ORG/reports" \
      >/tmp/airlock.reports 2>/dev/null || echo '{}' >/tmp/airlock.reports

    for VIEW in "requests per agent" "error rate per proxy" "latency per target"; do
      if grep -q "Agent Airlock: $VIEW" /tmp/airlock.reports; then
        ok "analytics view '$VIEW' exists"
      else
        bad "analytics view '$VIEW' exists" "not found -- run scripts/reports.sh"
      fi
    done

    STAT="https://apigee.googleapis.com/v1/organizations/$APIGEE_ORG/environments/$APIGEE_ENV/stats"
    RANGE="$(date -u -d '-24 hours' +'%m/%d/%Y %H:%M')~$(date -u +'%m/%d/%Y %H:%M')"
    # The stats API does not always answer. It is a control-plane endpoint with
    # its own rate limits, and a query that works perfectly well thirty seconds
    # later can come back empty, 429, or not at all. So it is retried rather than
    # trusted first time, and a silent API reports as itself: "this report would
    # render empty" and "Apigee was busy" are very different findings, and only
    # one of them is about this gateway.
    stat_rows() { # dimension select -- prints a row count, or "unreachable"
      local attempt out
      for attempt in 1 2 3; do
        out="$(curl -sS -G -H "Authorization: Bearer $TOK" "$STAT/$1" \
          --data-urlencode "select=$2" --data-urlencode "timeRange=$RANGE" \
          --max-time 40 2>/dev/null \
          | python -c "
import json,sys
try: d = json.load(sys.stdin)
except ValueError: print('unreachable'); raise SystemExit
if 'error' in d: print('unreachable'); raise SystemExit
print(sum(len(e.get('dimensions') or []) for e in d.get('environments', [])))
")"
        case "$out" in
          unreachable|"") [ "$attempt" = 3 ] || sleep 5 ;;
          *) printf '%s' "$out"; return 0 ;;
        esac
      done
      printf 'unreachable'
    }
    ROWS_A="$(stat_rows developer_app 'sum(message_count)')"
    ROWS_B="$(stat_rows apiproxy 'sum(message_count),sum(is_error)')"
    ROWS_C="$(stat_rows target_host 'avg(target_response_time),max(target_response_time)')"
    case "$ROWS_A/$ROWS_B/$ROWS_C" in
      *unreachable*)
        skip "each view's metrics and dimensions return rows from Analytics" \
             "the stats API did not answer after three tries -- inconclusive" ;;
      *)
        if [ "$ROWS_A" -gt 0 ] && [ "$ROWS_B" -gt 0 ] && [ "$ROWS_C" -gt 0 ]; then
          ok "each view's metrics and dimensions return rows from Analytics"
        else
          bad "each view's metrics and dimensions return rows from Analytics" \
              "rows: developer_app=$ROWS_A apiproxy=$ROWS_B target_host=$ROWS_C -- a report would render empty"
        fi ;;
    esac
  else
    skip "analytics views exist and return rows" "no gcloud access token"
  fi

  # p95 is computed from the audit log rather than by Apigee, and this asserts
  # the reason rather than taking it on trust: if a percentile function ever
  # appears in the stats API, this test starts failing and the workaround can go.
  #
  # Both outcomes are identified positively, because the interesting one is the
  # absence of an error, and that is also exactly what a failed request looks
  # like. Testing only for an error field meant any hiccup on the control plane
  # -- a timeout, a 429, an empty body -- announced that Apigee had grown a
  # percentile function and this workaround could be deleted. A canary that
  # cries wolf in the direction of "go remove the workaround" is worse than none.
  if [ -n "${TOK:-}" ]; then
    P95="$(curl -sS -G -H "Authorization: Bearer $TOK" \
         "https://apigee.googleapis.com/v1/organizations/$APIGEE_ORG/environments/$APIGEE_ENV/stats/target_host" \
         --data-urlencode "select=p95(target_response_time)" \
         --data-urlencode "timeRange=$RANGE" --max-time 40 2>/dev/null)"
    if printf '%s' "$P95" | grep -q 'not supported'; then
      ok "p95 comes from the audit log because Apigee has no percentile function"
    elif printf '%s' "$P95" | grep -q '"environments"'; then
      bad "p95 comes from the audit log because Apigee has no percentile function" \
          "the stats API now accepts p95 -- move the view into Apigee and drop tests/latency_p95.py"
    else
      skip "p95 comes from the audit log because Apigee has no percentile function" \
           "the stats API did not answer -- inconclusive, not evidence either way"
    fi
  fi

  # And the log-side calculation itself: it fails only if records are arriving
  # with no timings at all, which would mean the audit records that a request
  # happened without recording what it cost.
  if command -v python >/dev/null 2>&1 && command -v gcloud >/dev/null 2>&1; then
    if python "$HERE/../tests/latency_p95.py" --hours 24 >/tmp/airlock.p95 2>&1; then
      ok "p95 latency per target is computable from the audit log"
    else
      bad "p95 latency per target is computable from the audit log" "$(tail -4 /tmp/airlock.p95)"
    fi
  fi
echo
fi

# ---------------------------------------------------------------- M9
if want M9; then
echo "M9 -- llm-v1 model gateway"
  # The guard's pure functions under Node; the gateway tests below prove the
  # same file behaves identically inside Rhino.
  if command -v node >/dev/null 2>&1; then
    if node "$HERE/../tests/test_llm_guard.js" >/tmp/airlock.node 2>&1; then
      ok "llm_guard.js unit tests ($(grep -c '^  ok' /tmp/airlock.node) cases)"
    else
      bad "llm_guard.js unit tests" "$(grep '^  FAIL' -A1 /tmp/airlock.node | head -6)"
    fi
  else
    skip "llm_guard.js unit tests" "node not installed"
  fi

  CHAT="$APIGEE_BASE/llm/v1/chat/completions"
  JSONH='Content-Type: application/json'
  # The first entry of the allowlist is the one this suite spends money on.
  # Override with LLM_SMOKE_MODEL if the first entry is the expensive one.
  MODEL="${LLM_SMOKE_MODEL:-}"
  [ -n "$MODEL" ] || MODEL="${LLM_ALLOWED_MODELS:-}"
  MODEL="${MODEL%%,*}"
  CAP="${LLM_MAX_TOKENS:-1024}"

  status_is "no API key -> 401" 401 \
    "$(req POST "$CHAT" -H "$JSONH" --data '{"model":"any","messages":[]}' --max-time 25)"

  if [ -z "${AGENT_READER_KEY:-}" ]; then
    skip "llm-v1 gateway tests" "AGENT_READER_KEY unset"
  elif [ -z "$MODEL" ]; then
    skip "llm-v1 gateway tests" "LLM_ALLOWED_MODELS unset -- nothing is allowlisted"
  else
    RK="x-api-key: $AGENT_READER_KEY"
    BEARER="Authorization: Bearer $AGENT_READER_KEY"
    PROMPT='{"model":"'"$MODEL"'","messages":[{"role":"user","content":"Reply with the single word: ok"}]}'

    # Agents speak OpenAI, and OpenAI clients send the key as a bearer token.
    # Accepting both spellings is the whole point of EV-Bearer-Key, so both are
    # tested; if only one were, the proxy could lose the other silently.
    # The completion this call returns is also the sample for the leak check
    # below, so that check costs nothing extra. A gateway that forwards its own
    # upstream credential, or merely names the upstream, has told the agent where
    # to go around it. The two verdicts are reported together because the leak
    # check has nothing to read unless this one produced a body -- and reporting
    # nothing at all, as an earlier version did, made the suite's test count
    # depend on whether the free tier was busy.
    LIVE="bearer key + allowlisted model -> 200 with non-empty content"
    LEAK="response names neither the upstream key nor the upstream"
    code="$(req_llm POST "$CHAT" -H "$BEARER" -H "$JSONH" --data "$PROMPT" --max-time 90)"
    b="$(body)"
    if ! llm_answered "$LIVE" "$code"; then
      skip "$LEAK" "no completion came back to inspect"
    elif [ "$code" = "200" ] && echo "$b" | grep -q '"content":"[^"]'; then
      ok "$LIVE"
      if echo "$b" | grep -qiE 'sk-or-|openrouter'; then
        bad "$LEAK" "$(echo "$b" | head -c 300)"
      else
        ok "$LEAK"
      fi
    else
      bad "$LIVE" "HTTP $code -- $(echo "$b" | head -c 300)"
      skip "$LEAK" "no completion came back to inspect"
    fi

    code="$(req_llm POST "$CHAT" -H "$RK" -H "$JSONH" --data "$PROMPT" --max-time 90)"
    llm_answered "x-api-key spelling -> 200" "$code" \
      && status_is "x-api-key spelling -> 200" 200 "$code"

    # A denial must not double as a directory. If the refusal echoed the model
    # asked for, or listed what would have been accepted, an agent could map the
    # allowlist by guessing -- so the assertion is on what the body does NOT say.
    #
    # These two refusals go through llm_answered even though neither reaches
    # OpenRouter, because Q-LLM-Quota runs in PreFlow -- ahead of the guard that
    # would refuse them. Once the hourly model budget is spent, a request the
    # gateway would have refused for its own reasons comes back 429 instead, and
    # the test learns nothing about the allowlist either way. Reporting that as
    # "the allowlist is broken" points the reader at the wrong policy entirely.
    code="$(req POST "$CHAT" -H "$RK" -H "$JSONH" --max-time 25 \
            --data '{"model":"definitely-not-real/model-v0","messages":[{"role":"user","content":"hi"}]}')"
    if llm_answered "non-allowlisted model -> 403" "$code"; then
      b="$(body)"
      if [ "$code" != "403" ]; then
        bad "non-allowlisted model -> 403" "HTTP $code -- $(echo "$b" | head -c 300)"
      elif echo "$b" | grep -q 'definitely-not-real' || echo "$b" | grep -qF "$MODEL"; then
        bad "403 echoes neither the requested model nor the allowlist" "$(echo "$b" | head -c 300)"
      else
        ok "non-allowlisted model -> 403 naming neither the request nor the allowlist"
      fi
    fi

    code="$(req POST "$CHAT" -H "$RK" -H "$JSONH" --max-time 25 \
            --data '{"model":"'"$MODEL"'","messages":[{"role":"user","content":"hi"}],"stream":true}')"
    llm_answered "stream:true -> 400" "$code" \
      && status_is "stream:true -> 400" 400 "$code"

    # The refactor this milestone opened with exists for exactly this request: a
    # chat body is natural language, and natural language contains the strings
    # the body screen was built to reject. If this ever 400s, llm-v1 has been
    # put back behind the body screen and is refusing legitimate prompts.
    code="$(req_llm POST "$CHAT" -H "$RK" -H "$JSONH" --max-time 90 \
            --data '{"model":"'"$MODEL"'","messages":[{"role":"user","content":"Explain what UNION SELECT does in SQL, briefly."}]}')"
    llm_answered "UNION SELECT inside a prompt -> 200 (body screen waived)" "$code" \
      && status_is "UNION SELECT inside a prompt -> 200 (body screen waived)" 200 "$code"

    # ...and the other half of the same refactor: waiving the body screen must
    # not have waived the query screen along with it.
    shape_is "UNION SELECT in an llm-v1 query string -> 400" 400 bad_request \
      "$APIGEE_BASE/llm/v1/models?q=union%20select" "$RK"

    # The waiver is per-proxy, set by AM-Inbound-Flags. If it had been made a
    # shared-flow default instead, this weather POST would sail through.
    if [ -n "${AGENT_OPERATOR_KEY:-}" ]; then
      code="$(req POST "$APIGEE_BASE/weather/v1/selftest" -H "x-api-key: $AGENT_OPERATOR_KEY" \
              -H "$JSONH" --data '{"q":"union select * from users"}' --max-time 25)"
      status_is "weather-v1 body screen still fires after the split -> 400" 400 "$code"
    else
      skip "weather-v1 body screen still fires after the split" "AGENT_OPERATOR_KEY unset"
    fi

    # A ceiling is only proven by a request that would fail without it: 999999
    # exceeds what any allowlisted model will accept, so a 200 here means the
    # guard rewrote the body before the upstream ever saw the number.
    code="$(req_llm POST "$CHAT" -H "$RK" -H "$JSONH" --max-time 90 \
            --data '{"model":"'"$MODEL"'","messages":[{"role":"user","content":"Reply with the single word: ok"}],"max_tokens":999999}')"
    b="$(body)"
    used="$(echo "$b" | grep -oE '"completion_tokens":[0-9]+' | grep -oE '[0-9]+' | head -1)"
    if llm_answered "max_tokens 999999 clamped to the configured ceiling" "$code"; then
      if [ "$code" = "200" ] && [ -n "$used" ] && [ "$used" -le "$CAP" ]; then
        ok "max_tokens 999999 clamped to the configured ceiling ($used <= $CAP)"
      else
        bad "max_tokens 999999 clamped to the configured ceiling" "HTTP $code used=${used:-none} cap=$CAP -- $(echo "$b" | head -c 300)"
      fi
    fi

    # An upstream error status raises no Apigee fault, so sf-fault-sanitizer
    # never sees it and the body reaches the caller exactly as the upstream
    # wrote it. That is how a retired free tier once answered a caller with
    # OpenRouter's own pricing copy and this gateway's upstream account id.
    # A bad temperature is the cheapest way to make the upstream refuse:
    # the guard has no opinion about it, so the request really does travel.
    code="$(req_llm POST "$CHAT" -H "$RK" -H "$JSONH" --max-time 60 \
            --data '{"model":"'"$MODEL"'","messages":[],"temperature":"hot"}')"
    b="$(body)"
    # A 429 is the one non-200 this test cannot use: it is either the tier or the
    # gateway's own quota answering, so the upstream never wrote the body that is
    # under examination here.
    if llm_answered "upstream error body is replaced, not forwarded" "$code"; then
      if [ "$code" != "200" ] && echo "$b" | grep -q '"upstream_error"' \
         && ! echo "$b" | grep -qiE 'openrouter|user_id|sk-or-'; then
        ok "upstream error body is replaced, not forwarded (HTTP $code)"
      else
        bad "upstream error body is replaced, not forwarded" "HTTP $code -- $(echo "$b" | head -c 300)"
      fi
    fi

    # Quota exhaustion is real traffic against a real budget: running it would
    # spend the reader's whole hourly model allowance and leave every test above
    # failing for the next hour. So it is opt-in, and skipped loudly rather than
    # quietly dropped.
    if [ "${AIRLOCK_QUOTA_TEST:-}" = "1" ]; then
      LQ="${LLM_QUOTA_READER:-30}"
      hit=""
      for i in $(seq 1 $((LQ + 2))); do
        code="$(req POST "$CHAT" -H "$RK" -H "$JSONH" --max-time 90 \
                --data '{"model":"'"$MODEL"'","messages":[{"role":"user","content":"ok"}]}')"
        [ "$code" = "429" ] && { hit="$i"; break; }
      done
      if [ -n "$hit" ]; then ok "reader exhausts llm_quota -> 429 (at call $hit)"
      else bad "reader exhausts llm_quota -> 429" "no 429 in $((LQ + 2)) calls"; fi

      # The model budget is a separate counter, not the product's. Weather must
      # still answer on the very same key.
      code="$(req GET "$APIGEE_BASE/weather/v1/forecast?latitude=43.7&longitude=-79.4&current=temperature_2m" \
              -H "$RK" --max-time 25)"
      status_is "weather GET on the same key still 200 after llm_quota exhaustion" 200 "$code"
    else
      skip "llm_quota exhaustion -> 429" "set AIRLOCK_QUOTA_TEST=1; it spends the hourly model budget"
    fi
  fi
echo
fi

# ---------------------------------------------------------------- M10
if want M10; then
echo "M10 -- model spend in the audit, and the alarm that watches it"
  LLM_METRIC="${LLM_AUDIT_METRIC:-airlock_llm_tokens}"
  LLM_THRESHOLD="${LLM_ALERT_THRESHOLD:-2000}"

  # The one metric in this project whose value is not 1, and the reason it is
  # asserted field by field rather than just looked up: a counter of model calls
  # is not a measure of model spend. Ten one-word questions and one document
  # summary are the same call count and nothing like the same bill, so if the
  # valueExtractor were ever dropped the metric would keep reporting, keep
  # graphing, and quietly answer a different question than the alarm asks.
  MET_LLM="log-based metric '$LLM_METRIC' sums tokens rather than counting calls"
  if ! command -v gcloud >/dev/null 2>&1; then
    skip "$MET_LLM" "gcloud not installed"
  elif gcloud logging metrics describe "$LLM_METRIC" --project "$APIGEE_ORG" \
       --format json >/tmp/airlock.llmmetric 2>&1; then
    if ! grep -q 'llm.chat' /tmp/airlock.llmmetric; then
      bad "$MET_LLM" "filter does not mention llm.chat"
    elif ! grep -q 'EXTRACT(jsonPayload.tokens_total)' /tmp/airlock.llmmetric; then
      bad "$MET_LLM" "no valueExtractor on tokens_total -- this counts calls, not tokens"
    elif ! grep -q 'DISTRIBUTION' /tmp/airlock.llmmetric; then
      # Cloud Logging accepts a valueExtractor only on a distribution metric, so
      # an INT64 spelling of this is rejected at creation. That is worth an
      # assertion rather than a comment: the rejection is what monitoring.sh
      # threw away for a whole run, leaving no metric, no alarm, and a script
      # that said it had created both.
      bad "$MET_LLM" "not a DISTRIBUTION metric, so the value extractor cannot apply"
    elif ! grep -q 'tokens_total>0' /tmp/airlock.llmmetric; then
      # A refusal carries no tokens_total at all, and an absent field extracts
      # as zero. Without this clause the series fills with points that mean
      # "refused" and read as "free", which is the wrong shape of wrong: the
      # graph looks healthier the more the gateway is being abused.
      bad "$MET_LLM" "filter does not exclude records without a token count"
    else
      ok "$MET_LLM"
    fi
  else
    bad "$MET_LLM" "not found -- run scripts/monitoring.sh"
  fi

  POL_LLM="alert policy fires above $LLM_THRESHOLD tokens per agent per hour"
  if ! command -v gcloud >/dev/null 2>&1; then
    skip "$POL_LLM" "gcloud not installed"
  elif gcloud alpha monitoring policies list --project "$APIGEE_ORG" --format json \
       >/tmp/airlock.pol 2>/dev/null && grep -q "$LLM_METRIC" /tmp/airlock.pol; then
    if python "$HERE/../tests/check_alert_policy.py" "$LLM_METRIC" "$LLM_THRESHOLD" \
       </tmp/airlock.pol >/tmp/airlock.polq 2>&1; then
      ok "$POL_LLM"
    else
      bad "$POL_LLM" "$(head -4 /tmp/airlock.polq)"
    fi
  else
    skip "$POL_LLM" "no policy watches $LLM_METRIC -- run scripts/monitoring.sh"
  fi

  # ---- the live half: one refused model call, one served one, both audited.
  AUDIT_LOG="${AUDIT_LOG_NAME:-agent-airlock-audit}"
  AUDIT_FILTER="logName=\"projects/$APIGEE_ORG/logs/$AUDIT_LOG\""
  CHAT="$APIGEE_BASE/llm/v1/chat/completions"
  JSONH='Content-Type: application/json'
  MODEL="${LLM_SMOKE_MODEL:-}"
  [ -n "$MODEL" ] || MODEL="${LLM_ALLOWED_MODELS:-}"
  MODEL="${MODEL%%,*}"

  A_DENIED="a refused model request is audited as denied, naming agent and model"
  A_SPEND="a served model call is audited with its token spend"
  A_QUIET="no prompt text reaches the audit log"

  if [ -z "${AGENT_READER_KEY:-}" ] || [ -z "$MODEL" ] || ! command -v gcloud >/dev/null 2>&1; then
    WHY="AGENT_READER_KEY, an allowlisted model and gcloud are all needed"
    skip "$A_DENIED" "$WHY"
    skip "$A_SPEND" "$WHY"
    skip "$A_QUIET" "$WHY"
  else
    RK="x-api-key: $AGENT_READER_KEY"
    # A string no model would emit and no other test sends, carried in the prompt
    # of both calls below. Its absence from the window is the only direct evidence
    # that the audit records what was spent without recording what was said -- an
    # inspection of the schema proves the fields are absent, not that the text is.
    CANARY="airlock-canary-$$-$(date -u +%s)"
    export AIRLOCK_PROMPT_CANARY="$CANARY"
    SINCE="$(date -u -d '-30 seconds' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%SZ)"

    # Refused first, and with bare req: a model the allowlist rejects never
    # reaches the upstream, so this call cannot be rate-limited by the provider
    # and costs nothing to retry-free.
    #
    # It can still be refused by the wrong policy, though. Q-LLM-Quota runs in
    # PreFlow, ahead of the guard, so once this key's hourly model budget is gone
    # the request is throttled before the allowlist ever sees it -- and what lands
    # in the audit is a `throttled` record, not a `denied` one. That is the gateway
    # behaving correctly and the test having nothing to look at, so it skips.
    dcode="$(req POST "$CHAT" -H "$RK" -H "$JSONH" --max-time 25 \
             --data '{"model":"definitely-not-real/model-v0","messages":[{"role":"user","content":"'"$CANARY"'"}]}')"
    DENIED=""
    if llm_answered "$A_DENIED" "$dcode"; then DENIED=1; fi

    # Served second. max_tokens is deliberately tiny: this test is about whether
    # the spend was recorded, not how much of it there was, and every token here
    # comes out of the same hourly budget the tests above are spending.
    code="$(req_llm POST "$CHAT" -H "$RK" -H "$JSONH" --max-time 90 \
            --data '{"model":"'"$MODEL"'","messages":[{"role":"user","content":"Reply with the single word: '"$CANARY"'"}],"max_tokens":16}')"
    SERVED=""
    if llm_answered "$A_SPEND" "$code"; then SERVED=1; fi

    ENTRIES='[]'
    for _ in 1 2 3 4 5 6 7 8 9 10 11 12; do
      ENTRIES="$(gcloud logging read "$AUDIT_FILTER AND jsonPayload.action=\"llm.chat\" AND timestamp>=\"$SINCE\"" \
        --project "$APIGEE_ORG" --limit 50 --order asc --format json 2>/dev/null)"
      [ -n "$ENTRIES" ] || ENTRIES='[]'
      printf '%s' "$ENTRIES" >/tmp/airlock.llmentries
      # The same lesson M7 learned: break on the evidence, not on a count. The
      # filter is narrowed to llm.chat so an unrelated record cannot end the
      # poll, and each assertion is only waited on if its call actually happened
      # -- otherwise a spent budget costs two minutes of polling for a record
      # that was never going to be written.
      if { [ -z "$DENIED" ] \
           || python "$HERE/../tests/check_audit_entries.py" llm_denied </tmp/airlock.llmentries >/dev/null 2>&1; } \
         && { [ -z "$SERVED" ] \
              || python "$HERE/../tests/check_audit_entries.py" llm_spend </tmp/airlock.llmentries >/dev/null 2>&1; }; then
        break
      fi
      sleep 10
    done

    llm_q() { python "$HERE/../tests/check_audit_entries.py" "$1" </tmp/airlock.llmentries; }

    if [ -n "$DENIED" ]; then
      if llm_q llm_denied >/tmp/airlock.aq 2>&1; then
        ok "$A_DENIED"
      else
        bad "$A_DENIED" "$(head -4 /tmp/airlock.aq)"
      fi
    fi

    if [ -n "$SERVED" ]; then
      if llm_q llm_spend >/tmp/airlock.aq 2>&1; then
        ok "$A_SPEND"
      else
        bad "$A_SPEND" "$(head -4 /tmp/airlock.aq)"
      fi
    fi

    # Checked over the whole window rather than inside llm_spend alone, because
    # the refused call carried the canary too and its record is written whether
    # or not the free tier felt like answering the served one.
    if grep -qF "$CANARY" /tmp/airlock.llmentries; then
      bad "$A_QUIET" "the canary from the prompt is in the audit window"
    else
      ok "$A_QUIET"
    fi
    unset AIRLOCK_PROMPT_CANARY
  fi
echo
fi

# ---------------------------------------------------------------- M11
if want M11; then
echo "M11 -- ADK agents: one identity across the model plane and the tool plane"
  ADKDIR="$HERE/../adk-agents"
  AUDIT_LOG="${AUDIT_LOG_NAME:-agent-airlock-audit}"
  AUDIT_FILTER="logName=\"projects/$APIGEE_ORG/logs/$AUDIT_LOG\""

  # Unit: the startup contract. --no-project is deliberate -- these tests import
  # the factory's configuration half and neither ADK nor LiteLLM, so they must
  # also pass on a machine where the agent stack was never installed. That is
  # the machine where somebody has just exported OPENAI_API_KEY to make
  # something else work, which is exactly when these refusals are worth having.
  U_ADK="agent startup contract unit tests"
  if ! command -v uv >/dev/null 2>&1; then
    skip "$U_ADK" "uv not installed"
  elif uv run --with pytest --with requests --no-project \
        python -m pytest "$HERE/../tests/test_adk_agents.py" -q >/tmp/airlock.adk 2>&1; then
    ok "$U_ADK ($(grep -oE '[0-9]+ passed' /tmp/airlock.adk | head -1))"
  else
    bad "$U_ADK" "$(grep -E '^(FAILED|E  |assert)' /tmp/airlock.adk | head -6)"
  fi

  # ---- the live half: one real turn, and what the gateway saw of it.
  A_TURN="the reader agent answers a weather question holding no credential"
  A_MODEL="that turn is audited as llm.chat by agent-reader"
  A_TOOL="its tool call is audited under the same agent and the same key"

  # This suite is carrying the credentials the agent must not have: config/env.sh
  # exports .env wholesale so provision.sh can fill the KVM from it, which leaves
  # OPENROUTER_API_KEY and the GitHub PAT in the environment of every test in
  # this file. They are unset for the child rather than the agent's check
  # relaxed. The list is read out of factory.py rather than restated here,
  # because a name added there and forgotten here would leave this test quietly
  # handing the agent the one credential the milestone exists to keep from it.
  FORBIDDEN_NAMES="$(sed -n '/^FORBIDDEN_ENV = (/,/^)/p' \
                       "$ADKDIR/airlock_common/factory.py" \
                     | grep -oE '"[A-Z][A-Z0-9_]*"' | tr -d '"' | tr '\n' ' ')"

  if [ -z "$FORBIDDEN_NAMES" ]; then
    # A failure, not a skip. An empty list means the derivation broke, and
    # carrying on would launch the agent with the suite's own credentials in its
    # environment -- which either fails loudly for the wrong reason or, worse,
    # passes.
    WHY_M11="FORBIDDEN_ENV could not be read out of factory.py"
    bad "$A_TURN" "$WHY_M11 -- refusing to launch an agent without stripping the environment"
    skip "$A_MODEL" "$WHY_M11"
    skip "$A_TOOL" "$WHY_M11"
  elif [ -z "${AGENT_READER_KEY:-}" ] || ! command -v uv >/dev/null 2>&1 \
       || ! command -v gcloud >/dev/null 2>&1; then
    WHY_M11="AGENT_READER_KEY, uv and gcloud are all needed"
    skip "$A_TURN" "$WHY_M11"
    skip "$A_MODEL" "$WHY_M11"
    skip "$A_TOOL" "$WHY_M11"
  else
    SINCE="$(date -u -d '-30 seconds' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%SZ)"

    # A question no model can answer out of its weights: the forecast has to come
    # from the tool, so a turn that passes has exercised both planes and not one.
    ( for n in $FORBIDDEN_NAMES; do unset "$n"; done
      uv run --directory "$ADKDIR" python "$HERE/../tests/run_agent_turn.py" \
        airlock_reader "What is the weather in Lahore right now? Answer in one short sentence." \
    ) >/tmp/airlock.turn 2>/tmp/airlock.turnerr
    TURN=$?

    # run_agent_turn.py's exit codes, because stderr cannot tell an
    # infrastructure problem from a policy one. 5 is the interesting failure:
    # the agent refused to start, which is this milestone's own contract
    # breaking rather than anything upstream having a bad day.
    TURNED=""
    case "$TURN" in
      0) if [ -s /tmp/airlock.turn ]; then ok "$A_TURN"; TURNED=1
         else bad "$A_TURN" "exit 0 but the agent produced no text"; fi ;;
      3) skip "$A_TURN" "agent stack not installed: uv sync --directory adk-agents" ;;
      4) skip "$A_TURN" "the free tier is rate-limiting; nothing here is the gateway's doing" ;;
      5) bad "$A_TURN" "the agent refused to start -- $(tail -2 /tmp/airlock.turnerr)" ;;
      *) bad "$A_TURN" "$(tail -3 /tmp/airlock.turnerr)" ;;
    esac

    if [ -z "$TURNED" ]; then
      skip "$A_MODEL" "no turn completed, so there is nothing to find in the audit"
      skip "$A_TOOL" "no turn completed, so there is nothing to find in the audit"
    else
      # Poll on the evidence rather than a count, as M7 and M10 do: the model
      # record and the tool record are written by two different proxies and
      # arrive independently, so a window holding one is not yet the window this
      # milestone is claiming.
      for _ in 1 2 3 4 5 6 7 8 9 10 11 12; do
        gcloud logging read "$AUDIT_FILTER AND timestamp>=\"$SINCE\"" \
          --project "$APIGEE_ORG" --limit 100 --order asc --format json \
          >/tmp/airlock.turnentries 2>/dev/null
        [ -s /tmp/airlock.turnentries ] || printf '[]' >/tmp/airlock.turnentries
        if python "$HERE/../tests/check_audit_entries.py" session_tool agent-reader \
             </tmp/airlock.turnentries >/dev/null 2>&1; then
          break
        fi
        sleep 10
      done

      turn_q() { python "$HERE/../tests/check_audit_entries.py" "$1" agent-reader \
                   </tmp/airlock.turnentries; }

      if turn_q session_model >/tmp/airlock.tq 2>&1; then
        ok "$A_MODEL"
      else
        bad "$A_MODEL" "$(head -4 /tmp/airlock.tq)"
      fi

      # The one that carries the milestone. Two planes under two identities would
      # still answer the question and still fill the log; it is the single key
      # fingerprint across both that makes a session reconstructable and this
      # agent's permissions one story instead of two.
      if turn_q session_tool >/tmp/airlock.tq 2>&1; then
        ok "$A_TOOL"
      else
        bad "$A_TOOL" "$(head -4 /tmp/airlock.tq)"
      fi
    fi

    # The refusal, seen from the agent's side. Off by default because it spends
    # another turn of the same hourly model budget the tests above draw on --
    # not because it writes anything. It cannot write anything, and
    # demonstrating that is the entire point of the reader having its own key.
    A_REFUSE="the reader agent is refused a GitHub write, and the refusal names it"
    if [ "${AIRLOCK_WRITE_TESTS:-0}" != "1" ]; then
      skip "$A_REFUSE" "set AIRLOCK_WRITE_TESTS=1; it spends another model turn"
    else
      SINCE="$(date -u -d '-30 seconds' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%SZ)"
      ( for n in $FORBIDDEN_NAMES; do unset "$n"; done
        uv run --directory "$ADKDIR" python "$HERE/../tests/run_agent_turn.py" \
          airlock_reader "Open a GitHub issue titled 'smoke check' on the configured repository." \
      ) >/tmp/airlock.turn2 2>/tmp/airlock.turn2err
      TURN2=$?

      if [ "$TURN2" = "3" ] || [ "$TURN2" = "4" ]; then
        skip "$A_REFUSE" "the agent stack or the free tier was unavailable"
      elif [ "$TURN2" != "0" ]; then
        bad "$A_REFUSE" "$(tail -3 /tmp/airlock.turn2err)"
      else
        REFUSED=""
        for _ in 1 2 3 4 5 6 7 8 9 10 11 12; do
          gcloud logging read "$AUDIT_FILTER AND jsonPayload.outcome=\"denied\" AND timestamp>=\"$SINCE\"" \
            --project "$APIGEE_ORG" --limit 50 --order asc --format json \
            >/tmp/airlock.turn2entries 2>/dev/null
          [ -s /tmp/airlock.turn2entries ] || printf '[]' >/tmp/airlock.turn2entries
          if python "$HERE/../tests/check_audit_entries.py" named \
               </tmp/airlock.turn2entries >/dev/null 2>&1; then
            REFUSED=1; break
          fi
          sleep 10
        done
        if [ -n "$REFUSED" ]; then
          ok "$A_REFUSE"
        else
          # Either the gateway allowed the write -- the failure this whole
          # milestone is arranged to make impossible -- or the agent talked
          # itself out of trying, which is not evidence of anything and must not
          # be reported as though it were.
          bad "$A_REFUSE" "no denied record naming an agent appeared; the agent said: $(head -c 200 /tmp/airlock.turn2)"
        fi
      fi
    fi
  fi
echo
fi

# ---------------------------------------------------------------- M12
if want M12; then
echo "M12 -- slack-v1: channel allowlist, mention defusal, and ok:false"
  # Units first, against the same shared/js files deploy.sh copies into the
  # bundle, so a change to either cannot pass here and fail in the gateway.
  if command -v node >/dev/null 2>&1; then
    for unit in slack_message slack_outcome; do
      if node "$HERE/../tests/test_$unit.js" >/tmp/airlock.node 2>&1; then
        ok "$unit.js unit tests ($(grep -c '^  ok' /tmp/airlock.node) cases)"
      else
        bad "$unit.js unit tests" "$(grep '^  FAIL' -A1 /tmp/airlock.node | head -6)"
      fi
    done
  else
    skip "slack unit tests" "node not installed"
  fi

  SL="$APIGEE_BASE/slack/v1"
  # Syntactically valid and deliberately not allowlisted. A real-looking ID
  # matters: a 403 then proves the allowlist fired rather than a shape check.
  OTHERCH="C0000000000"

  # ---- static: the bot token must not be reachable from this repository ----
  if git -C "$HERE/.." grep -InE 'xox[baprs]-[A-Za-z0-9-]{10,}' -- . >/tmp/airlock.slk 2>/dev/null; then
    bad "no Slack token literal in tracked files" "$(head -c 200 /tmp/airlock.slk)"
  else
    ok "no Slack token literal in tracked files"
  fi

  if [ -n "${SLACK_BOT_TOKEN:-}" ]; then
    if grep -rIF -- "$SLACK_BOT_TOKEN" "$HERE/.." --exclude-dir=.git --exclude=.env >/dev/null 2>&1; then
      bad "live Slack token absent from committable files" "found outside .env"
    else
      ok "live Slack token absent from committable files"
    fi
  else
    skip "live Slack token absent from committable files" "SLACK_BOT_TOKEN unset"
  fi

  if [ -n "${AGENT_READER_KEY:-}" ] && [ -n "${AGENT_OPERATOR_KEY:-}" ]; then
    RK="x-api-key: $AGENT_READER_KEY"; OKH="x-api-key: $AGENT_OPERATOR_KEY"

    # Fixed before the first live call, not after the last one, so the audit
    # window below covers every request this milestone makes even on a box where
    # `date -d` is not GNU's and the fallback resolves to "now".
    SLACK_SINCE="$(date -u -d '-2 minutes' +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u +%Y-%m-%dT%H:%M:%SZ)"

    status_is "slack: no API key -> 401" 401 \
      "$(req GET "$SL/conversations.history?channel=$OTHERCH" --max-time 25)"

    # Scope, decided by the API Product before any proxy logic runs.
    code="$(req POST "$SL/chat.postMessage" -H "$RK" -H 'Content-Type: application/json' \
            --data "{\"channel\":\"$OTHERCH\",\"text\":\"should not be posted\"}" --max-time 25)"
    if [ "$code" = "403" ] && body | grep -q 'not scoped'; then
      ok "reader cannot post a message -> 403 scope"
    else
      bad "reader cannot post a message -> 403 scope" "HTTP $code -- $(body | head -c 200)"
    fi

    # Blast radius, and Slack makes this sharper than GitHub did: the Web API is
    # one flat namespace of a couple of hundred methods, most of them writes, all
    # reachable with the same token. Three methods appear in the products; the
    # bot's own scopes are far wider than that, and nothing else must be callable
    # through this gateway even for the operator.
    for m in "/conversations.list" "/users.list" "/chat.delete" "/files.upload" "/admin.users.list"; do
      code="$(req GET "$SL$m" -H "$OKH" --max-time 25)"
      if [ "$code" = "403" ] || [ "$code" = "404" ]; then
        ok "operator blocked from $m (HTTP $code)"
      else
        bad "operator blocked from $m" "HTTP $code -- $(body | head -c 200)"
      fi
    done

    # Same reasoning as M5's ALLOW_PROVISIONED: what .env says is not evidence
    # about the gateway. The allowlist lives in a KVM, one entry per channel.
    CH="$(printf '%s' "${SLACK_ALLOWED_CHANNELS:-}" | cut -d, -f1 | tr -d '[:space:]')"
    CH_PROVISIONED=""
    if [ -n "$CH" ] && command -v gcloud >/dev/null 2>&1; then
      if curl -sS -H "Authorization: Bearer $(token)" \
           "https://apigee.googleapis.com/v1/organizations/$APIGEE_ORG/environments/$APIGEE_ENV/keyvaluemaps/gateway-config/entries" \
           2>/dev/null | grep -q "\"slack_channel_$CH\""; then
        CH_PROVISIONED=yes
      fi
    fi

    if [ -n "$CH" ] && [ -n "$CH_PROVISIONED" ]; then
      # The headline test: the caller holds no Slack credential, yet an
      # authenticated Slack call succeeds. auth.test addresses no channel, so it
      # isolates the KVM injection from the allowlist.
      code="$(req GET "$SL/auth.test" -H "$RK" --max-time 30)"
      b="$(body)"
      if [ "$code" = "200" ] && echo "$b" | grep -q '"ok":true'; then
        ok "auth.test succeeds with no caller credential (token injected by gateway)"
      else
        bad "auth.test succeeds with no caller credential" "HTTP $code -- $(echo "$b" | head -c 200)"
      fi

      code="$(req GET "$SL/conversations.history?channel=$CH&limit=5" -H "$RK" --max-time 30)"
      b="$(body)"
      case "$code" in
        200) ok "reader reads an allowlisted channel -> 200" ;;
        403) bad "reader reads an allowlisted channel -> 200" \
                 "HTTP 403: the bot may not be in $CH, or a scope is missing -- $(echo "$b" | head -c 200)" ;;
        502) bad "reader reads an allowlisted channel -> 200" \
                 "HTTP 502: the gateway could not authenticate to Slack; check slack_bot_token in the KVM" ;;
        *)   bad "reader reads an allowlisted channel -> 200" "HTTP $code -- $(echo "$b" | head -c 200)" ;;
      esac

      # A Slack response carries the bot's own identity but must never carry a
      # credential back out.
      if echo "$b" | grep -qiE 'xox[baprs]-|"authorization"'; then
        bad "no credential material in the Slack response" "$(echo "$b" | head -c 160)"
      else
        ok "no credential material in the Slack response"
      fi

      # The allowlist, on both verbs. The refusal must not confirm what was
      # asked for: an agent walking the ID space must learn nothing from the
      # error text, which is also why slack_outcome.js drops Slack's own
      # channel_not_found before the body is returned.
      for probe in "GET|$SL/conversations.history?channel=$OTHERCH" "POST|$SL/chat.postMessage"; do
        verb="${probe%%|*}"; url="${probe#*|}"
        if [ "$verb" = "POST" ]; then
          code="$(req POST "$url" -H "$OKH" -H 'Content-Type: application/json' \
                  --data "{\"channel\":\"$OTHERCH\",\"text\":\"should not be posted\"}" --max-time 25)"
        else
          code="$(req GET "$url" -H "$OKH" --max-time 25)"
        fi
        b="$(body)"
        if [ "$code" = "403" ] && echo "$b" | grep -q 'not authorized for that Slack channel'; then
          if echo "$b" | grep -q "$OTHERCH"; then
            bad "non-allowlisted channel -> 403 on $verb without echoing it" "body echoed the channel"
          else
            ok "non-allowlisted channel -> 403 on $verb without echoing it"
          fi
        else
          bad "non-allowlisted channel -> 403 on $verb without echoing it" "HTTP $code -- $(echo "$b" | head -c 200)"
        fi
      done

      # Validation runs before the upstream call, so these post nothing.
      for bad_body in '{"text":"no channel"}' "{\"channel\":\"$CH\"}" "{\"channel\":\"$CH\",\"text\":\"  \"}" 'not json at all' '["array"]'; do
        code="$(req POST "$SL/chat.postMessage" -H "$OKH" -H 'Content-Type: application/json' \
                --data "$bad_body" --max-time 25)"
        if [ "$code" = "400" ] && body | grep -q '"error":"bad_request"'; then
          ok "malformed message rejected before upstream: $(echo "$bad_body" | head -c 24)"
        else
          bad "malformed message rejected before upstream: $(echo "$bad_body" | head -c 24)" "HTTP $code -- $(body | head -c 200)"
        fi
      done

      # Posting is visible to every human in the channel the moment it lands --
      # more visible than an issue on a test repository -- so it is opt-in.
      if [ "${AIRLOCK_WRITE_TESTS:-}" = "1" ]; then
        stamp="$(date -u +%Y%m%dT%H%M%SZ)"
        # Every extra field is the test. Slack would accept all of them: blocks
        # and attachments smuggle interactive elements into a channel, username
        # and icon_emoji let an agent post as somebody else, and <!channel> pages
        # the workspace straight out of the message text.
        payload="$(printf '{"channel":"%s","text":"airlock smoke %s <!channel> cc <@U000000000>","blocks":[{"type":"section","text":{"type":"mrkdwn","text":"x"}}],"attachments":[{"text":"x"}],"username":"Head of Security","icon_emoji":":lock:","link_names":true}' "$CH" "$stamp")"
        code="$(req POST "$SL/chat.postMessage" -H "$OKH" -H 'Content-Type: application/json' \
                --data "$payload" --max-time 30)"
        b="$(body)"
        if [ "$code" = "200" ] && echo "$b" | grep -q '"ok":true'; then
          ok "operator posts to an allowlisted channel -> 200"
          if echo "$b" | grep -q '@channel' && ! echo "$b" | grep -q '<!channel>'; then
            ok "the broadcast markup arrived defused, so nobody's phone lit up"
          else
            bad "the broadcast markup arrived defused" "$(echo "$b" | head -c 300)"
          fi
          if echo "$b" | grep -q '"username":"Head of Security"' || echo "$b" | grep -q '"blocks"'; then
            bad "impersonation and blocks stripped from the posted message" "$(echo "$b" | head -c 400)"
          else
            ok "impersonation and blocks stripped from the posted message"
          fi
        else
          bad "operator posts to an allowlisted channel -> 200" "HTTP $code -- $(echo "$b" | head -c 250)"
        fi
      else
        skip "message posting tests" "set AIRLOCK_WRITE_TESTS=1 -- they post real messages to $CH"
      fi

      # The audit is where a Slack write is reconstructed, and Slack is the one
      # backend that answers a refusal with HTTP 200. If slack_outcome.js were
      # ever removed the calls above would still pass; this is the test that
      # would not, because the record would read "ok" on a call that did nothing.
      if command -v gcloud >/dev/null 2>&1; then
        AUDIT_LOG="${AUDIT_LOG_NAME:-agent-airlock-audit}"
        SLACK_ENTRIES='[]'
        for _ in 1 2 3 4 5 6; do
          SLACK_ENTRIES="$(gcloud logging read \
            "logName=\"projects/$APIGEE_ORG/logs/$AUDIT_LOG\" AND timestamp>=\"$SLACK_SINCE\" AND jsonPayload.proxy=\"slack-v1\"" \
            --project "$APIGEE_ORG" --limit 50 --order asc --format json 2>/dev/null)"
          [ -n "$SLACK_ENTRIES" ] || SLACK_ENTRIES='[]'
          printf '%s' "$SLACK_ENTRIES" >/tmp/airlock.slack.entries
          grep -q '"slack.messages.read"' /tmp/airlock.slack.entries && \
            grep -q '"outcome": *"denied"' /tmp/airlock.slack.entries && break
          sleep 10
        done
        if grep -q '"slack.messages.read"' /tmp/airlock.slack.entries; then
          ok "a slack read is audited under its own action"
        else
          bad "a slack read is audited under its own action" "$(head -c 200 /tmp/airlock.slack.entries)"
        fi
        if grep -q "\"$OTHERCH\"" /tmp/airlock.slack.entries; then
          ok "the refused channel is named in the audit, though never in the reply"
        else
          bad "the refused channel is named in the audit" "no record carried $OTHERCH"
        fi
        if grep -q '"outcome": *"denied"' /tmp/airlock.slack.entries; then
          ok "a channel refusal is audited as denied"
        else
          bad "a channel refusal is audited as denied" "$(head -c 200 /tmp/airlock.slack.entries)"
        fi
      else
        skip "slack audit records" "gcloud not installed"
      fi
    elif [ -n "$CH" ]; then
      # The same one assertion M5 makes about an unprovisioned repo allowlist,
      # for the same reason: a missing KVM entry leaves slack.allowed_channel
      # null, and a null comparison that came out "equal" would hand the bot
      # token every channel in the workspace.
      code="$(req GET "$SL/conversations.history?channel=$CH" -H "$RK" --max-time 25)"
      if [ "$code" = "403" ]; then
        ok "an unprovisioned allowlist closes slack rather than opening it"
      else
        bad "an unprovisioned allowlist closes slack rather than opening it" \
            "HTTP $code -- a missing allowlist admitted a request"
      fi
      skip "allowlisted-channel tests" "gateway-config/slack_channel_$CH is not provisioned -- run: SLACK_BOT_TOKEN=... SLACK_ALLOWED_CHANNELS=$CH bash scripts/provision.sh"
    else
      skip "allowlisted-channel tests" "SLACK_ALLOWED_CHANNELS unset; see scripts/provision.sh"
    fi
  else
    skip "slack-v1 gateway tests" "agent keys unset; run scripts/provision.sh"
  fi
echo
fi

echo "-------------------------------------------"
echo "passed=$PASS failed=$FAIL skipped=$SKIP"
[ "$FAIL" -eq 0 ] || exit 1
