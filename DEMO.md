# Demo — Agent Airlock

A runnable walkthrough of the gateway, in eight acts. Every command here is real
and every expected output was produced by this deployment. Read
[ARCHITECTURE.md](ARCHITECTURE.md) first if you want to know *why* each control
exists; this file is about showing that it works.

Total run time: about **20 minutes** for the full sequence, or **4 minutes** for
the short path (Acts 0, 2, 5 and 7).

---

## Before you start

Run everything from the repository root in a bash shell. One line sets up the
whole session:

```bash
cd /c/path/to/apigee-mcp-gateway && . config/env.sh
```

That sources `.env` and exports `APIGEE_BASE`, `AGENT_READER_KEY`,
`AGENT_OPERATOR_KEY`, `GITHUB_ALLOWED_REPO` and the org/env names. Confirm the
session is live before an audience is watching:

```bash
echo "$APIGEE_BASE"; [ -n "$AGENT_READER_KEY" ] && echo "reader key loaded"; [ -n "$AGENT_OPERATOR_KEY" ] && echo "operator key loaded"
```

```
https://YOUR_LB_IP.nip.io
reader key loaded
operator key loaded
```

Three shorthand variables used throughout:

```bash
FC="$APIGEE_BASE/weather/v1/forecast?latitude=43.7&longitude=-79.4&current=temperature_2m"
AR="$APIGEE_BASE/weather/v1/archive?latitude=43.7&longitude=-79.4&start_date=2024-01-01&end_date=2024-01-02&daily=temperature_2m_max"
GH="$APIGEE_BASE/github/v1"
```

**One warning before Act 5.** Everything in this demo is read-only or refused,
with a single exception that is clearly marked: creating a GitHub issue is a
real, visible side effect on a real repository. It is behind an explicit opt-in
flag and it is the only step that leaves anything behind.

---

## The demo at a glance

| Act | Time | What it proves |
| --- | --- | --- |
| 0 | 3 min | The whole thing passes its own regression suite, 67 assertions |
| 1 | 1 min | No key and a wrong key both get nothing |
| 2 | 2 min | Two identities, same URL, different answers |
| 3 | 1 min | Refusals leak no internals and no reconnaissance |
| 4 | 3 min | Hostile input is stopped inbound; secrets are stripped outbound |
| 5 | 4 min | The gateway spends a credential the agent has never seen |
| 6 | 3 min | The same controls hold when a real LLM is driving |
| 7 | 3 min | The full session can be reconstructed after the fact |
| 8 | 3 min | Sustained abuse raises an alarm even when nothing succeeds |

---

## Act 0 — it passes its own tests

Start here. It is the least dramatic slide and the most convincing one.

```bash
bash scripts/smoke.sh
```

```
Gateway: https://YOUR_LB_IP.nip.io   org=your-gcp-project-id env=eval

M0 -- provisioning & routing
  PASS env 'eval' exists
  PASS gateway reachable over TLS (HTTP 404)
...
M7 -- audit trail, metric and alert
  PASS p95 latency per target is computable from the audit log

passed=67 failed=0 skipped=0
```

The suite is cumulative: every milestone's assertions keep running in all the
later ones, so a regression anywhere fails the whole run. Filter to one section
when you want to talk over a single control:

```bash
bash scripts/smoke.sh M5
```

Assertions that need a credential the machine does not have **skip with a stated
reason** rather than failing, so a clean run on a fresh checkout is honest about
what it did not check.

---

## Act 1 — the door is locked

```bash
curl -s -o /dev/null -w 'no key:   %{http_code}\n' "$FC"
curl -s -o /dev/null -w 'bad key:  %{http_code}\n' -H "x-api-key: not-a-real-key" "$FC"
curl -s -o /dev/null -w 'real key: %{http_code}\n' -H "x-api-key: $AGENT_READER_KEY" "$FC"
```

```
no key:   401
bad key:  401
real key: 200
```

And the successful call really is proxied weather, not a canned response:

```bash
curl -s -H "x-api-key: $AGENT_READER_KEY" "$FC" | head -c 200
```

```json
{"latitude":43.75,"longitude":-79.375,"generationtime_ms":0.03,…,"current":{"time":"2026-08-23T03:00","interval":900,"temperature_2m":18.4}}
```

**The point:** the backend is public and needs no credential at all. The key is
not protecting Open-Meteo — it is establishing *which agent is calling*, which
is what every control after this one depends on.

---

## Act 2 — identity decides scope

The strongest two-command demo in the set. Same URL, same gateway, same second;
only the key changes.

```bash
curl -s -o /dev/null -w 'reader   -> archive: %{http_code}\n' -H "x-api-key: $AGENT_READER_KEY"   "$AR"
curl -s -o /dev/null -w 'operator -> archive: %{http_code}\n' -H "x-api-key: $AGENT_OPERATOR_KEY" "$AR"
```

```
reader   -> archive: 403
operator -> archive: 200
```

The 403 is not a rule inside the proxy. It comes from the API Product bound to
the reader's key, and Apigee raises it before the proxy's own logic runs. There
is no prompt, no tool argument and no retry that gets past it, because it is a
fact about the credential rather than about the request.

Show what the reader is actually told:

```bash
curl -s -H "x-api-key: $AGENT_READER_KEY" "$AR"
```

```json
{"error":"forbidden","message":"This credential is not scoped for that operation."}
```

---

## Act 3 — a refusal says nothing useful

Every error, whatever raised it, leaves through one sanitizer and arrives in the
same shape:

```bash
for h in "" "x-api-key: nope" "x-api-key: $AGENT_READER_KEY"; do
  if [ -z "$h" ]; then curl -s "$FC"; else curl -s -H "$h" "$AR"; fi; echo
done
```

```json
{"error":"unauthorized","message":"A valid API key is required."}
{"error":"unauthorized","message":"A valid API key is required."}
{"error":"forbidden","message":"This credential is not scoped for that operation."}
```

Confirm there is nothing else in there:

```bash
curl -s -H "x-api-key: nope" "$FC" | grep -Ei 'apigee|policy|revision|stack|steps' && echo "LEAK" || echo "clean"
```

```
clean
```

**The point:** Apigee's native fault text names policies, revisions and
internals. None of it reaches the caller, so a refusal cannot be used to map the
gateway.

---

## Act 4 — hostile in, sanitized out

### Inbound: injection shapes never reach the backend

```bash
for q in "'%20OR%201=1" "union%20select" "%3Cscript%3E" "javascript%3Aevil"; do
  printf '%-22s ' "$q"
  curl -s -H "x-api-key: $AGENT_READER_KEY" "$APIGEE_BASE/weather/v1/forecast?latitude=43.7&longitude=-79.4&q=$q"
  echo
done
```

```
'%20OR%201=1           {"error":"bad_request","message":"The request was rejected as malformed or unsafe."}
union%20select         {"error":"bad_request","message":"The request was rejected as malformed or unsafe."}
%3Cscript%3E           {"error":"bad_request","message":"The request was rejected as malformed or unsafe."}
javascript%3Aevil      {"error":"bad_request","message":"The request was rejected as malformed or unsafe."}
```

The control that makes this meaningful — a clean query on the same endpoint still
works, so the 400s came from the policy and not from a broken flow:

```bash
curl -s -o /dev/null -w 'clean query: %{http_code}\n' -H "x-api-key: $AGENT_READER_KEY" "$FC"
```

```
clean query: 200
```

### Inbound: a JSON bomb

Fifty levels of nesting, refused before any downstream parser sees it:

```bash
python -c "print('{\"a\":'*50 + '1' + '}'*50)" > /tmp/deep.json
curl -s -X POST -H "x-api-key: $AGENT_OPERATOR_KEY" -H 'Content-Type: application/json' \
     --data-binary @/tmp/deep.json "$APIGEE_BASE/weather/v1/selftest"
```

```json
{"error":"bad_request","message":"The request was rejected as malformed or unsafe."}
```

```bash
curl -s -o /dev/null -w 'shallow body (control): %{http_code}\n' -X POST \
     -H "x-api-key: $AGENT_OPERATOR_KEY" -H 'Content-Type: application/json' \
     --data '{"a":{"b":1}}' "$APIGEE_BASE/weather/v1/selftest"
```

```
shallow body (control): 200
```

### Outbound: redaction

`/weather/v1/selftest` returns a canned payload carrying every credential shape
plus two email addresses, so the scrubber can be proven end to end without a
backend that has to be persuaded to leak something:

```bash
curl -s -H "x-api-key: $AGENT_OPERATOR_KEY" "$APIGEE_BASE/weather/v1/selftest"
```

```json
{"ok":true,"id":7,"user":{"name":"Ada","email":"a***@example.com"},
 "note":"contact b***@example.org for access","nested":{"items":[{"id":1}]}}
```

Every key matching token / secret / password / api_key / authorization is gone
entirely — not masked, *removed* — and both addresses are masked to their first
character. `ok`, `id` and the nested structure survive untouched, which is the
half that matters: a scrubber that breaks the payload gets turned off.

Prove the negative directly:

```bash
curl -s -H "x-api-key: $AGENT_OPERATOR_KEY" "$APIGEE_BASE/weather/v1/selftest" \
  | grep -Eo 'access_token|api_key|refresh_token|password|abc123|sk-not-real|hunter2' || echo "nothing sensitive survived"
```

```
nothing sensitive survived
```

---

## Act 5 — the credential the agent has never seen

This is the centrepiece. The gateway holds a GitHub PAT in an encrypted KVM;
nothing else in this repository, this shell, or the agent's process has it.

### It works

```bash
curl -s -o /dev/null -w 'allowlisted repo: %{http_code}\n' \
  -H "x-api-key: $AGENT_READER_KEY" "$GH/repos/$GITHUB_ALLOWED_REPO/issues"
```

```
allowlisted repo: 200
```

The caller sent no GitHub credential. Apigee stripped the agent's key on the way
out, read the PAT from `backend-secrets`, and set `Authorization` microseconds
before the socket opened.

### Nothing comes back that shouldn't

```bash
curl -s -H "x-api-key: $AGENT_READER_KEY" "$GH/repos/$GITHUB_ALLOWED_REPO/issues" \
  | grep -Eo 'ghp_[A-Za-z0-9]+|github_pat_[A-Za-z0-9_]+|"token"|"authorization"' || echo "no credential material in the response"
```

```
no credential material in the response
```

### The PAT may only be spent on one repository

```bash
curl -s -H "x-api-key: $AGENT_OPERATOR_KEY" "$GH/repos/octocat/Hello-World/issues"
```

```json
{"error":"forbidden","message":"This credential is not authorized for that repository."}
```

Two things worth saying aloud here. The PAT may well be valid for that
repository — the gateway simply will not spend it there. And the refusal does
not name what was asked for, so the response cannot be used to enumerate what
the allowlist contains.

### Almost all of GitHub is unreachable, even for the operator

```bash
for p in "/repos/octocat/Hello-World/pulls" "/user/repos" "/user" "/repos/$GITHUB_ALLOWED_REPO/issues/1/comments"; do
  printf '%-48s ' "$p"; curl -s -o /dev/null -w '%{http_code}\n' -H "x-api-key: $AGENT_OPERATOR_KEY" "$GH$p"
done
```

```
/repos/octocat/Hello-World/pulls                 404
/user/repos                                      404
/user                                            404
/repos/…/issues/1/comments                       404
```

Only `/repos/{owner}/{repo}/issues` is declared in either product, and both
proxies end their flow list with `RF-Unknown-Resource`. Undeclared paths are
rejected, never forwarded — the stored PAT is far more privileged than the one
endpoint agents can reach with it.

### The reader cannot write

```bash
curl -s -X POST -H "x-api-key: $AGENT_READER_KEY" -H 'Content-Type: application/json' \
     --data '{"title":"should not be created"}' "$GH/repos/$GITHUB_ALLOWED_REPO/issues"
```

```json
{"error":"forbidden","message":"This credential is not scoped for that operation."}
```

### The operator can — and only within the allowlist

> **This creates a real issue on a real repository.** It is the only step in the
> demo with a side effect, which is why it is opt-in. Close the issue afterwards.

```bash
AIRLOCK_WRITE_TESTS=1 bash scripts/smoke.sh M5
```

```
  PASS operator creates an issue -> 201
  PASS assignees stripped from the created issue
  PASS labels and milestone stripped from the created issue
```

Those last two are the interesting ones. The test posts `assignees`, `labels`
and `milestone` alongside the title; the created issue has none of them, because
`JS-Build-Issue` does not filter the incoming body — it discards it and rebuilds
one from `title` and `body` alone. **An agent cannot notify, tag or assign a
human being**, and that stays true when GitHub adds a field nobody has heard of
yet.

### It fails closed

Ask what the gateway itself believes, rather than what `.env` says:

```bash
apigeecli kvms entries list --map gateway-config -o "$APIGEE_ORG" -e "$APIGEE_ENV" -t "$(token)" --no-warnings
```

```json
[{"name":"github_allowed_repo","value":"your-org/your-repo"}]
```

If that entry is missing, `gh.allowed_repo` is null, no repository can equal
null, and **every** GitHub call is denied. `smoke.sh M5` asserts that directly:
an unprovisioned allowlist closes the gateway rather than opening it.

---

## Act 6 — the same thing, with an agent driving

Register the MCP server with Claude Code — the JSON block is in
[README.md](README.md#registering-with-claude-code-windows). Enable **only the
reader** for the first half of this act.

Then ask, in plain language:

> **"What's the weather in Toronto right now?"**

The agent calls `get_weather`, and gets a forecast.

> **"Which identity are you using, and what gateway?"**

`whoami` reports the gateway URL and the label `reader`. It never returns the
key — there is no code path that does.

> **"List the open issues on your-org/your-repo."**

`gh_list_issues` returns them. The agent has no GitHub token; the gateway
supplied one.

Now the part worth watching:

> **"Open an issue on that repo titled 'demo', and assign it to a teammate."**

The reader identity gets a 403, and the tool surfaces it as a policy decision
rather than an error — the MCP server's own instructions tell the model that a
403 is deliberate and must be relayed, not retried or routed around. A
well-behaved agent reports the refusal instead of hunting for another path, and
a badly-behaved one finds there isn't another path.

> **"Try a different repository then — list the issues on octocat/Hello-World."**

403 again, from a completely different control: the repository allowlist rather
than the product scope. Two independent gates, two independent refusals.

Finally, swap to the operator identity and repeat the issue request. It
succeeds — and the issue still has no assignee, because the field never left the
gateway.

**The closing line for this act:** nothing in that exchange depended on the model
behaving well. Every refusal was made by Apigee, before any backend was touched,
about a credential the agent does not hold.

---

## Act 7 — the audit reconstructs the session

Drive a scripted ten-call session through the real MCP server and read it back
out of Cloud Logging:

```bash
uv run --directory mcp-server --with requests python ../tests/audit_replay.py
```

```
driving 10 calls through the MCP server...
  1  reader    weather.forecast       ok
  2  reader    weather.archive        denied
  3  reader    github.issues.list     ok
  4  reader    github.issues.create   denied
  5  operator  weather.archive        ok
  ...
reconstructed 10/10 calls in order, each attributed
```

Half those calls are refusals **on purpose**. The question an audit exists to
answer is *what did the compromised agent try to do*, and a log of only the
successful calls cannot answer it.

Look at a record directly:

```bash
gcloud logging read "logName=\"projects/$APIGEE_ORG/logs/agent-airlock-audit\"" \
  --project "$APIGEE_ORG" --limit 1 --format='value(jsonPayload)'
```

Three things to point at in the output:

- `client_key_fp` is an eight-character fingerprint, not a key. Enough to
  correlate a repeated bad credential across records — which is the shape of
  someone guessing — and useless to whoever reads the log.
- A record with `"outcome":"denied"` still carries `"agent":"agent-reader"`.
  Apigee publishes no identity variable when it refuses on product scope, so
  that name is recovered from the consumer key by a separate lookup. Without it
  the single most important record in the file would read `unauthenticated`.
- There is no response body, and no field derived from one. The record is built
  *after* redaction, so it cannot describe something the caller was not allowed
  to see.

And the latency the Apigee console cannot give you:

```bash
python tests/latency_p95.py --hours 24
```

```
target                        n    avg     p95     max
api.github.com               34   241ms   402ms   611ms
api.open-meteo.com           58    38ms    71ms   118ms
gateway overhead (total-target)    ~94ms
```

p95 is computed here rather than in Apigee because the stats API has no
percentile function — and worse, it does not validate metric names, so a report
selecting `p95_total_response_time` is created successfully and then renders
nothing. `smoke.sh M7` asserts that `p95(...)` is *still* rejected, so if Apigee
ever grows one, the test fails and this workaround gets deleted.

---

## Act 8 — sustained abuse raises an alarm

Twenty-five denied write attempts, with the **reader** key. Nothing is created,
no repository is touched, and the PAT is never even read — every one of these is
refused at the product scope:

```bash
for i in $(seq 1 25); do curl -s -o /dev/null -X POST -H "x-api-key: $AGENT_READER_KEY" -H 'Content-Type: application/json' -d '{"title":"alert drill"}' "$APIGEE_BASE/github/v1/repos/octocat/Hello-World/issues"; sleep 0.5; done
```

The `sleep` keeps it under the 10-per-second SpikeArrest, which would otherwise
convert the attempts into throttles and count them under a different outcome.

A few minutes later the alert policy fires — metric `airlock_github_writes`,
threshold 20 per agent per hour, one-hour aligned sum — and the email arrives.
The incident auto-closes after 30 minutes.

Check the wiring without waiting:

```bash
gcloud logging metrics describe airlock_github_writes --project "$APIGEE_ORG" --format='value(filter)'
gcloud alpha monitoring policies list --project "$APIGEE_ORG" --format='value(displayName,enabled)'
```

**The point:** an agent that has been prompt-injected into hammering a forbidden
write looks exactly like this — and it is visible without a single attempt
having succeeded. Alerting only on successful writes would show nothing at all
here, which is the wrong time to be quiet.

---

## Closing numbers

| | |
| --- | --- |
| Assertions in the regression suite | **67**, cumulative across 8 milestones |
| Backend credentials in the agent's process | **0** |
| GitHub endpoints reachable through the gateway | **1** — `/repos/{owner}/{repo}/issues` |
| Repositories the PAT may be spent on | **1**, held in a KVM, changeable without a redeploy |
| Gateway overhead | **~90–100 ms** per request |
| Requests that produce an audit record | **all of them**, including every refusal |

---

## If something does not work

| Symptom | Cause | Fix |
| --- | --- | --- |
| Everything returns 401 | `.env` not sourced, or keys revoked | `. config/env.sh`, then re-run `scripts/provision.sh` |
| GitHub calls 403 with "not authorized for that repository" | The KVM value is not `owner/repo` — a pasted browser URL is the usual culprit | `python scripts/normalize_repo.py "<what you have>"`, then re-provision |
| Every GitHub call 403 including the allowlisted repo | `gateway-config/github_allowed_repo` is missing | Export `GITHUB_ALLOWED_REPO` and re-run `scripts/provision.sh` — this is fail-closed behaving correctly |
| `smoke.sh M7` skips the analytics assertions | Apigee's stats API is rate-limited and did not answer in three tries | Re-run; the suite reports silence as inconclusive rather than guessing |
| MCP server exits immediately at startup | A backend token is set in the environment | Unset `GITHUB_TOKEN` / `GITHUB_PAT` / `GH_TOKEN`; the crash is deliberate |
| Write tests skipped | Opt-in flag absent | `AIRLOCK_WRITE_TESTS=1 bash scripts/smoke.sh M5` |

---

## Afterwards

Act 5's write test creates one GitHub issue titled `airlock smoke <timestamp>`.
Close it. It is the only artifact the entire demo leaves behind — everything
else is either read-only or was refused before it reached a backend.
