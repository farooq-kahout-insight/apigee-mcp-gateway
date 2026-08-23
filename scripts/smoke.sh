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
      # Count records, not matching lines. The earlier version grepped for the
      # field name and broke out one record early, because each entry mentioned
      # it twice -- once in the payload and once in a log label.
      COUNT="$(printf '%s' "$ENTRIES" | python -c 'import json,sys; print(len(json.load(sys.stdin)))' 2>/dev/null || echo 0)"
      if [ "${COUNT:-0}" -ge 2 ]; then break; fi
      sleep 10
    done
    printf '%s' "$ENTRIES" >/tmp/airlock.entries

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

echo "-------------------------------------------"
echo "passed=$PASS failed=$FAIL skipped=$SKIP"
[ "$FAIL" -eq 0 ] || exit 1
