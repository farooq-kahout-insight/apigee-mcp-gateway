#!/usr/bin/env bash
# Idempotently create API products, the agent developer, and the agent apps.
# Writes the resulting consumer keys back into .env (keys only -- never secrets).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$HERE/.."
# Git Bash hands MSYS-style paths to native binaries fine, but Windows Python
# cannot open "/c/..." when it arrives inside a string argument. Convert first.
winpath() { cygpath -w "$1" 2>/dev/null || echo "$1"; }
. "$HERE/../config/env.sh"

TOKEN="$(token)"
[ -n "$TOKEN" ] || { echo "FATAL: no gcloud access token. Run: gcloud auth login" >&2; exit 1; }
A() { apigeecli "$@" -o "$APIGEE_ORG" -t "$TOKEN" --no-warnings --no-output; }

# ---------- backend credentials (encrypted KVMs) ----------
# Values arrive from the environment and are piped to curl on stdin, never
# passed as an argument: anything in argv is readable from the process table by
# any other process on the machine, and this token outlives the run.
CP="https://apigee.googleapis.com/v1/organizations/$APIGEE_ORG/environments/$APIGEE_ENV/keyvaluemaps"

kvm_create() { # map-name
  local code
  code="$(printf '{"name":"%s"}' "$1" | curl -sS -o /dev/null -w '%{http_code}' -X POST "$CP" \
          -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" --data-binary @-)"
  case "$code" in
    200|201) echo "    kvm $1 created" ;;
    409)     echo "    kvm $1 exists" ;;
    *)       echo "FATAL: creating kvm $1 -> HTTP $code" >&2; return 1 ;;
  esac
}

kvm_put() { # map-name entry-key env-var-name
  local map="$1" key="$2" var="$3" code
  # Apigee X has no upsert for entries: POST creates, PUT replaces. Try create,
  # fall back to update on conflict.
  code="$(python -c 'import json,os,sys,io; io.open(1,"w",encoding="utf-8",newline="\n",closefd=False).write(json.dumps({"name":sys.argv[1],"value":os.environ[sys.argv[2]]}))' "$key" "$var" \
          | curl -sS -o /dev/null -w '%{http_code}' -X POST "$CP/$map/entries" \
              -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" --data-binary @-)"
  if [ "$code" = "409" ]; then
    code="$(python -c 'import json,os,sys,io; io.open(1,"w",encoding="utf-8",newline="\n",closefd=False).write(json.dumps({"name":sys.argv[1],"value":os.environ[sys.argv[2]]}))' "$key" "$var" \
            | curl -sS -o /dev/null -w '%{http_code}' -X PUT "$CP/$map/entries/$key" \
                -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" --data-binary @-)"
  fi
  case "$code" in
    200|201) echo "    $map/$key set (value not shown)" ;;
    *)       echo "FATAL: setting $map/$key -> HTTP $code" >&2; return 1 ;;
  esac
}

echo "==> key value maps"
kvm_create backend-secrets
kvm_create gateway-config

if [ -n "${GITHUB_PAT:-}" ]; then
  kvm_put backend-secrets github_pat GITHUB_PAT
else
  echo "    SKIP github_pat -- export GITHUB_PAT to provision it"
fi

# The allowlist entry is the only thing standing between the stored PAT and
# every other repository on GitHub, and the gateway compares it literally against
# the two path segments it pulled out of the request. So the shape is checked
# here rather than discovered later: a browser URL pasted in whole -- the obvious
# thing to supply, and what was supplied the first time -- produces a value no
# request can ever equal, and the resulting refusal blames the caller's
# credential for being "not scoped for that operation". That is a false lead
# pointing at the wrong half of the system.
#
# A URL is accepted and reduced rather than rejected, because it says plainly
# which repository was meant. Anything that does not reduce to exactly
# owner/repo is fatal -- an allowlist nobody can satisfy is not a safe default,
# it is a gateway that has quietly stopped doing its job.
if [ -n "${GITHUB_ALLOWED_REPO:-}" ]; then
  GITHUB_ALLOWED_REPO="$(python "$(winpath "$ROOT/scripts/normalize_repo.py")" "$GITHUB_ALLOWED_REPO")" || {
    echo "FATAL: GITHUB_ALLOWED_REPO must name one repository as owner/repo" >&2
    echo "       (a github.com URL is accepted and reduced; anything else is not)" >&2
    exit 1
  }
  export GITHUB_ALLOWED_REPO
  echo "    allowlisting $GITHUB_ALLOWED_REPO"
  kvm_put gateway-config github_allowed_repo GITHUB_ALLOWED_REPO
else
  echo "    SKIP github_allowed_repo -- export GITHUB_ALLOWED_REPO (owner/repo)"
fi

# ---------- what a trace is allowed to show ----------
# A debug session is an operational surface like any other, and the audit's
# app-name lookup put a new secret on it: AccessEntity returns the whole app
# entity, and the whole app entity includes every consumer secret the app holds,
# in plaintext. Apigee masks client_id and access_token by default but knows
# nothing about that variable, so without this the credential the gateway exists
# to keep out of reach would be readable by anyone who can start a trace.
#
# Masked at the environment, not in the bundle, because a mask is a property of
# what may be observed here rather than of what any one proxy does -- and because
# it must already be in force before the proxy that needs it is deployed.
echo "==> debug mask"
MASKED_VARS='["AccessEntity.AE-Resolve-App"]'
code="$(printf '{"variables":%s}' "$MASKED_VARS" \
        | curl -sS -o /dev/null -w '%{http_code}' -X PATCH \
            "https://apigee.googleapis.com/v1/organizations/$APIGEE_ORG/environments/$APIGEE_ENV/debugmask?updateMask=variables" \
            -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" --data-binary @-)"
case "$code" in
  200) echo "    AccessEntity.AE-Resolve-App masked in traces" ;;
  *)   echo "FATAL: setting the debug mask -> HTTP $code" >&2; exit 1 ;;
esac

# ---------- API products ----------
# Quota lives on the product (M3) so limits are product-managed, not
# proxy-hardcoded: the Quota policy reads limit/interval/unit off the product at
# runtime. A product may override the default via a sibling "<name>.quota" file
# containing "<limit> <interval> <unit>".
for f in "$ROOT"/config/products/*.json; do
  name="$(basename "$f" .json)"
  qfile="$ROOT/config/products/$name.quota"
  if [ -f "$qfile" ]; then read -r QL QI QU < "$qfile"; else QL=100; QI=1; QU=hour; fi
  QUOTA_ARGS=(--quota "$QL" --interval "$QI" --unit "$QU")
  echo "==> product $name (quota ${QL}/${QI}${QU})"
  if A products get --name "$name" >/dev/null 2>&1; then
    A products update --name "$name" --display-name "$name" --opgrp "$f" --envs "$APIGEE_ENV"        --approval auto --attrs access=private "${QUOTA_ARGS[@]}"
    echo "    updated"
  else
    A products create --name "$name" --display-name "$name" --opgrp "$f"        --envs "$APIGEE_ENV" --approval auto --attrs access=private "${QUOTA_ARGS[@]}"
    echo "    created"
  fi
done

# ---------- developer ----------
DEV_EMAIL="$(python -c "import json,sys;print(json.load(open(sys.argv[1]))['developer']['email'])" "$(winpath "$ROOT/config/apps.json")")"
echo "==> developer $DEV_EMAIL"
if A developers get --email "$DEV_EMAIL" >/dev/null 2>&1; then
  echo "    exists"
else
  A developers create --email "$DEV_EMAIL" --first Agent --last Fleet --user agents
  echo "    created"
fi

# ---------- apps ----------
# Windows Python emits CRLF by default; force LF so the field values that become
# shell variable names are not silently suffixed with \r.
python - "$(winpath "$ROOT")" <<'PYA' > "$ROOT/.provision.apps"
import json, sys, io
root = sys.argv[1]
out = io.open(1, "w", encoding="utf-8", newline="\n", closefd=False)
for a in json.load(open(root + "/config/apps.json"))["apps"]:
    out.write("%s\t%s\t%s\n" % (a["name"], a["product"], a["keyvar"]))
out.flush()
PYA

while IFS=$'\t' read -r app prod keyvar; do
  [ -n "$app" ] || continue
  echo "==> app $app -> $prod"
  if A apps get --name "$app" >/dev/null 2>&1; then
    echo "    exists"
  else
    A apps create --name "$app" --email "$DEV_EMAIL" --prods "$prod"
    echo "    created"
  fi

  # One agent, one credential.
  #
  # `apigeecli apps update --prods` does not re-scope the key the app already
  # has: it mints a new one. Re-syncing the product list on every provision, as
  # this used to, therefore left the app holding a pile of live keys that nothing
  # had a record of -- five of them on agent-reader before anyone looked. An
  # identity whose credentials cannot be counted cannot be revoked either, which
  # is most of what having an identity is for here. So the product is attached to
  # the credential that already exists, and nothing new is issued.
  #
  # The key is chosen by issue time and not by list position, because Apigee
  # returns credentials unordered: reading credentials[0] meant .env could start
  # naming a different key between two runs that had changed nothing.
  read -r key needs_prod surplus <<EOF
$(apigeecli apps get --name "$app" -o "$APIGEE_ORG" -t "$TOKEN" --no-warnings 2>/dev/null \
  | python -c "
import json, sys
d = json.load(sys.stdin); a = d[0] if isinstance(d, list) else d
prod = sys.argv[1]
creds = sorted(a.get('credentials', []), key=lambda c: int(c.get('issuedAt') or 0))
live = [c for c in creds if c.get('status') == 'approved'] or creds
if not live:
    sys.exit(1)
keep = live[0]
attached = [p['apiproduct'] for p in keep.get('apiProducts', [])]
print(keep['consumerKey'],
      '0' if prod in attached else '1',
      ','.join(c['consumerKey'] for c in creds if c is not keep) or '-')
" "$prod" | tr -d '\r')
EOF
  [ -n "${key:-}" ] || { echo "FATAL: could not read consumer key for $app" >&2; exit 1; }

  if [ "$needs_prod" = "1" ]; then
    code="$(printf '{"apiProducts":["%s"]}' "$prod" \
            | curl -sS -o /dev/null -w '%{http_code}' -X POST \
                "https://apigee.googleapis.com/v1/organizations/$APIGEE_ORG/developers/$DEV_EMAIL/apps/$app/keys/$key" \
                -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" --data-binary @-)"
    case "$code" in
      200) echo "    $prod attached to the existing key" ;;
      *)   echo "FATAL: attaching $prod to $app's key -> HTTP $code" >&2; exit 1 ;;
    esac
  else
    echo "    scoped to $prod"
  fi

  # Surplus keys are reported rather than deleted: revoking a credential is not
  # this script's call to make silently, and one of them may be the key someone
  # is holding. But they are said out loud every run until they are gone, because
  # an unaccounted-for key is exactly the thing this gateway exists to not have.
  if [ "$surplus" != "-" ]; then
    n="$(printf '%s\n' "$surplus" | tr ',' '\n' | wc -l | tr -d ' ')"
    echo "    WARNING: $app holds $n other live credential(s) from earlier runs."
    echo "             Revoke each one, once you are sure nothing is using it:"
    printf '%s\n' "$surplus" | tr ',' '\n' | while read -r extra; do
      echo "               apigeecli apps keys delete --name $app --key $extra -d $DEV_EMAIL -o $APIGEE_ORG -t \$(gcloud auth print-access-token)"
    done
  fi

  # Persist the key into .env (create from example on first run).
  [ -f "$ROOT/.env" ] || cp "$ROOT/.env.example" "$ROOT/.env"
  python - "$(winpath "$ROOT/.env")" "$keyvar" "$key" <<'PYB'
import sys, re, io
path, var, val = sys.argv[1], sys.argv[2], sys.argv[3]
s = io.open(path, encoding="utf-8").read().replace("\r\n", "\n")
line = "%s=%s" % (var, val)
if re.search(r"(?m)^%s=" % re.escape(var), s):
    s = re.sub(r"(?m)^%s=.*$" % re.escape(var), line, s)
else:
    s = s.rstrip("\n") + "\n" + line + "\n"
io.open(path, "w", encoding="utf-8", newline="\n").write(s)
PYB
  echo "    ${keyvar} written to .env"
done < "$ROOT/.provision.apps"
rm -f "$ROOT/.provision.apps"

# ---------- the audit's write path ----------
# The proxies log to Cloud Logging as a service account rather than as Apigee
# itself, so the permission to write the audit is a thing that can be seen,
# granted and revoked on its own. deploy.sh passes it with -s; without it the
# CloudLogging policy fails at runtime with a permission error that arrives
# nowhere useful, because the failure happens after the response has gone out.
#
# This lived in the shell history for a while and is folded in here because
# rebuilding the org from this repo has to include it: an audit trail that
# silently stops writing when someone reprovisions is worse than none.
echo "==> audit logging service account"
SA_EMAIL="${APIGEE_DEPLOY_SA:-apigee-airlock-logger@${APIGEE_ORG}.iam.gserviceaccount.com}"
SA_ID="${SA_EMAIL%%@*}"

if gcloud iam service-accounts describe "$SA_EMAIL" --project "$APIGEE_ORG" >/dev/null 2>&1; then
  echo "    $SA_ID exists"
else
  gcloud iam service-accounts create "$SA_ID" --project "$APIGEE_ORG" \
    --display-name "Apigee Agent Airlock audit logger" \
    --description "Writes the agent-airlock-audit log from the gateway's PostClientFlow" \
    >/dev/null && echo "    $SA_ID created"
fi

# logWriter and nothing else. This identity's entire job is appending to one
# log; it must not be able to read the audit back, let alone reach anything else
# in the project.
if gcloud projects add-iam-policy-binding "$APIGEE_ORG" \
     --member "serviceAccount:$SA_EMAIL" --role roles/logging.logWriter \
     --condition None --quiet >/dev/null 2>&1; then
  echo "    roles/logging.logWriter granted"
else
  echo "    WARNING: could not grant roles/logging.logWriter -- the audit will"
  echo "             deploy cleanly and then write nothing. Grant it by hand."
fi

# Apigee's own service agent has to be able to mint tokens as the logger, or the
# runtime cannot assume the identity deploy.sh attached to the proxy.
PROJECT_NUM="$(gcloud projects describe "$APIGEE_ORG" --format 'value(projectNumber)' 2>/dev/null)"
if [ -n "$PROJECT_NUM" ]; then
  APIGEE_AGENT="service-${PROJECT_NUM}@gcp-sa-apigee.iam.gserviceaccount.com"
  if gcloud iam service-accounts add-iam-policy-binding "$SA_EMAIL" \
       --project "$APIGEE_ORG" --member "serviceAccount:$APIGEE_AGENT" \
       --role roles/iam.serviceAccountTokenCreator --quiet >/dev/null 2>&1; then
    echo "    apigee service agent may impersonate $SA_ID"
  else
    echo "    WARNING: could not let the Apigee service agent impersonate $SA_ID"
  fi
else
  echo "    WARNING: could not resolve the project number; skipped the"
  echo "             serviceAccountTokenCreator binding"
fi

echo "Provisioning complete."
