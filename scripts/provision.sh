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
    # Re-attach the product list so scope changes between milestones take effect.
    apigeecli apps update --name "$app" -e "$DEV_EMAIL" --prods "$prod" \
      -o "$APIGEE_ORG" -t "$TOKEN" --no-warnings --no-output || true
    echo "    exists (products re-synced)"
  else
    A apps create --name "$app" --email "$DEV_EMAIL" --prods "$prod"
    echo "    created"
  fi
  key="$(apigeecli apps get --name "$app" -o "$APIGEE_ORG" -t "$TOKEN" --no-warnings 2>/dev/null \
        | python -c "import json,sys; d=json.load(sys.stdin); a=d[0] if isinstance(d,list) else d; print(a['credentials'][0]['consumerKey'])" | tr -d '\r\n')"
  [ -n "$key" ] || { echo "FATAL: could not read consumer key for $app" >&2; exit 1; }
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

echo "Provisioning complete."
