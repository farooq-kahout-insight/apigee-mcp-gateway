# Demo — Agent Airlock

A runnable walkthrough of the gateway, in twelve acts. Every command here is
real, and every expected output came from this deployment. There is one
exception, marked at the top of Act 11, which has not been run live yet. Read
[ARCHITECTURE.md](ARCHITECTURE.md) first if you want to know *why* each control
exists. This file is about showing that it works.

Total run time: about **33 minutes** for the full sequence, or **4 minutes** for
the short path (Acts 0, 2, 5 and 7).

Acts 0–8 are the tool plane: an agent reaching a backend without holding a
credential. Acts 9 and 10 make the same argument about the model itself, which
is the credential agents normally *do* hold. Act 11 goes back to the tool plane
with the hardest of the three credentials — a Slack bot token, which cannot be
narrowed down before it reaches the gateway.

---

## Before you start

Run everything from the repository root in a bash shell. One line sets up the
whole session:

```bash
cd /c/path/to/apigee-mcp-gateway && . config/env.sh
```

That sources `.env` and exports `APIGEE_BASE`, `AGENT_READER_KEY`,
`AGENT_OPERATOR_KEY`, `GITHUB_ALLOWED_REPO`, `SLACK_ALLOWED_CHANNELS`,
`LLM_ALLOWED_MODELS` and the org/env names. Note what is *not* on that list.
`.env` holds no backend credential, so a shell set up for this demo cannot call
GitHub, Slack or OpenRouter directly, even by accident. Check the session is
live before an audience is watching:

```bash
echo "$APIGEE_BASE"; [ -n "$AGENT_READER_KEY" ] && echo "reader key loaded"; [ -n "$AGENT_OPERATOR_KEY" ] && echo "operator key loaded"
```

```
https://YOUR_LB_IP.nip.io
reader key loaded
operator key loaded
```

Six shorthand variables used throughout:

```bash
FC="$APIGEE_BASE/weather/v1/forecast?latitude=43.7&longitude=-79.4&current=temperature_2m"
AR="$APIGEE_BASE/weather/v1/archive?latitude=43.7&longitude=-79.4&start_date=2024-01-01&end_date=2024-01-02&daily=temperature_2m_max"
GH="$APIGEE_BASE/github/v1"
SLK="$APIGEE_BASE/slack/v1"
CHAT="$APIGEE_BASE/llm/v1/chat/completions"
MODEL="${LLM_ALLOWED_MODELS%%,*}"
```

`MODEL` takes the first entry of the allowlist, which is the model the suite
spends on too. The allowlisted models are free-tier ones, so Acts 9 and 10
sometimes get a `429` from the provider. That has nothing to do with the
gateway. The suite counts it as a skip rather than a failure, and so should
you.

**One warning before Acts 5 and 11.** Everything in this demo is read-only or
refused, with two exceptions. Both are clearly marked and both sit behind the
same opt-in flag: creating a GitHub issue, and posting a Slack message. The
Slack one is the more visible of the two. An issue on a test repository is seen
by whoever goes looking; a message in a channel is seen by everyone in it,
straight away.

---

## The demo at a glance

| Act | Time | What it proves |
| --- | --- | --- |
| 0 | 3 min | The whole thing passes its own regression suite, every assertion cumulative |
| 1 | 1 min | No key and a wrong key both get nothing |
| 2 | 2 min | Two identities, same URL, different answers |
| 3 | 1 min | Refusals leak no internals and no reconnaissance |
| 4 | 3 min | Hostile input is stopped inbound; secrets are stripped outbound |
| 5 | 4 min | The gateway spends a credential the agent has never seen |
| 6 | 3 min | The same controls hold when a real LLM is driving |
| 7 | 3 min | The full session can be reconstructed after the fact |
| 8 | 3 min | Sustained abuse raises an alarm even when nothing succeeds |
| 9 | 5 min | The model is behind the same airlock: allowlist, ceiling, no key |
| 10 | 3 min | One identity spans the model plane and the tool plane |
| 11 | 5 min | A credential that cannot be scoped upstream, confined here instead |

---

## Act 0 — it passes its own tests

Start here. It is the dullest part of the demo and the most convincing one.

```bash
bash scripts/smoke.sh
```

```
Gateway: https://YOUR_LB_IP.nip.io   org=your-gcp-project-id env=eval

M0 -- provisioning & routing
  PASS env 'eval' exists
  PASS gateway reachable over TLS (HTTP 404)
...
M9 -- llm-v1 model gateway
  PASS non-allowlisted model -> 403 naming neither the request nor the allowlist
...
M11 -- ADK agents: one identity across the model plane and the tool plane
  PASS agent startup contract unit tests (25 passed)

passed=90 failed=0 skipped=0
```

That footer is from the last full run before Slack was added. `M12` adds
roughly two dozen more assertions, so quote the number the run prints rather
than this one.

The suite is cumulative. Every milestone's assertions keep running in all the
later ones, so a break anywhere fails the whole run. Filter to one section when
you want to talk through a single control:

```bash
bash scripts/smoke.sh M5
```

Assertions that need a credential the machine does not have **skip, and say
why**, rather than failing. So a clean run on a fresh checkout is honest about
what it did not check.

The model milestones take that idea one step further, and it is worth saying to
an audience before it happens rather than after. Two things produce a `429`: a
free-tier model that rate-limits, and an hourly model quota the suite has just
spent on its own earlier assertions. Neither says anything about whether the
gateway is correct. Both skip too, and the skip names which of the two it was.
The rule the suite is built around is that **a failing run must mean the gateway
did something wrong**. Anything else teaches a room to ignore one.

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
not protecting Open-Meteo. It establishes *which agent is calling*, and every
control after this one depends on that.

---

## Act 2 — identity decides scope

The best two-command demo in the set. Same URL, same gateway, same second. Only
the key changes.

```bash
curl -s -o /dev/null -w 'reader   -> archive: %{http_code}\n' -H "x-api-key: $AGENT_READER_KEY"   "$AR"
curl -s -o /dev/null -w 'operator -> archive: %{http_code}\n' -H "x-api-key: $AGENT_OPERATOR_KEY" "$AR"
```

```
reader   -> archive: 403
operator -> archive: 200
```

The 403 is not a rule inside the proxy. It comes from the API Product bound to
the reader's key, and Apigee raises it before the proxy's own logic runs. No
prompt, no tool argument and no retry gets past it, because it is a fact about
the credential rather than about the request.

Show what the reader is actually told:

```bash
curl -s -H "x-api-key: $AGENT_READER_KEY" "$AR"
```

```json
{"error":"forbidden","message":"This credential is not scoped for that operation."}
```

---

## Act 3 — a refusal says nothing useful

Every error leaves through the same sanitizer, whatever raised it, and arrives
in the same shape:

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

**The point:** Apigee's own fault text names policies, revisions and other
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

The control that makes this mean something: a clean query on the same endpoint
still works, so the 400s came from the policy and not from a broken flow:

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

`/weather/v1/selftest` returns a canned payload holding every credential shape
plus two email addresses. That way the scrubber can be proven end to end without
having to talk a real backend into leaking something:

```bash
curl -s -H "x-api-key: $AGENT_OPERATOR_KEY" "$APIGEE_BASE/weather/v1/selftest"
```

```json
{"ok":true,"id":7,"user":{"name":"Ada","email":"a***@example.com"},
 "note":"contact b***@example.org for access","nested":{"items":[{"id":1}]}}
```

Every key matching token / secret / password / api_key / authorization is gone
entirely — not masked, *removed* — and both addresses are masked down to their
first character. `ok`, `id` and the nested structure come through untouched,
which is the half that matters: a scrubber that breaks the payload gets turned
off.

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

This is the main act. The gateway holds a GitHub PAT in an encrypted KVM.
Nothing else has it — not this repository, not this shell, not the agent's
process.

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

Two things worth saying out loud here. The PAT may well be valid for that
repository; the gateway simply will not spend it there. And the refusal does not
name what was asked for, so the response cannot be used to work out what is on
the allowlist.

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
proxies end their flow list with `RF-Unknown-Resource`. Paths that were never
declared are rejected, never forwarded. The stored PAT can do far more than the
one endpoint agents can reach with it.

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
and `milestone` alongside the title, and the created issue has none of them.
`JS-Build-Issue` does not filter the incoming body; it throws it away and builds
a new one from `title` and `body` alone. **An agent cannot notify, tag or assign
a human being**, and that stays true when GitHub adds a field nobody has heard
of yet.

### It fails closed

Ask the gateway what it believes, rather than trusting what `.env` says:

```bash
apigeecli kvms entries list --map gateway-config -o "$APIGEE_ORG" -e "$APIGEE_ENV" -t "$(token)" --no-warnings
```

```json
[{"name":"github_allowed_repo","value":"your-org/your-repo"}]
```

If that entry is missing, `gh.allowed_repo` is null, no repository can equal
null, and **every** GitHub call is denied. `smoke.sh M5` asserts that directly:
an allowlist nobody provisioned closes the gateway rather than opening it.

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

The reader gets a 403, and the tool reports it as a decision rather than an
error. The MCP server's own instructions tell the model that a 403 is deliberate
and must be passed on, not retried or worked around. A well-behaved agent
reports the refusal instead of hunting for another route. A badly behaved one
finds there is no other route.

> **"Try a different repository then — list the issues on octocat/Hello-World."**

403 again, from a completely different control: the repository allowlist rather
than the product scope. Two independent gates, two independent refusals.

Finally, switch to the operator identity and repeat the issue request. It
succeeds, and the issue still has no assignee, because that field never left the
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

- `client_key_fp` is an eight-character fingerprint, not a key. It is enough to
  match a repeated bad credential across records, which is what someone guessing
  looks like, and useless to whoever reads the log.
- A record with `"outcome":"denied"` still carries `"agent":"agent-reader"`.
  Apigee publishes no identity variable when it refuses on product scope, so the
  name is looked up from the consumer key separately. Without that lookup, the
  most important record in the file would read `unauthenticated`.
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
percentile function. Worse, it does not check metric names, so a report that
selects `p95_total_response_time` is created without complaint and then shows
nothing. `smoke.sh M7` asserts that `p95(...)` is *still* rejected, so if Apigee
ever adds one, the test fails and this workaround gets deleted.

---

## Act 8 — sustained abuse raises an alarm

Twenty-five denied write attempts, using the **reader** key. Nothing is created,
no repository is touched, and the PAT is never even read. Every one of these is
refused at the product scope:

```bash
for i in $(seq 1 25); do curl -s -o /dev/null -X POST -H "x-api-key: $AGENT_READER_KEY" -H 'Content-Type: application/json' -d '{"title":"alert drill"}' "$APIGEE_BASE/github/v1/repos/octocat/Hello-World/issues"; sleep 0.5; done
```

The `sleep` keeps it under the 10-per-second SpikeArrest, which would otherwise
turn the attempts into throttles and count them under a different outcome.

A few minutes later the alert policy fires — metric `airlock_github_writes`,
threshold 20 per agent per hour, one-hour aligned sum — and the notification
arrives by email *and* in Slack, on every channel named in
`ALERT_CHANNEL_TITLES`. The incident auto-closes after 30 minutes.

Slack is where an alert like this actually gets read, which is why it is wired
that way. But note what the wiring is not. That notification comes from Google's
own Monitoring bot, not from `slack-v1`. An alarm routed through the gateway it
is watching goes quiet at exactly the moment it matters. A revoked bot token, a
spent quota or a badly provisioned channel allowlist would each suppress the
alert about itself.

Check the wiring without waiting:

```bash
gcloud logging metrics describe airlock_github_writes --project "$APIGEE_ORG" --format='value(filter)'
gcloud alpha monitoring policies list --project "$APIGEE_ORG" --format='value(displayName,enabled)'
```

**The point:** an agent that has been prompt-injected into hammering a forbidden
write looks exactly like this, and it shows up without a single attempt having
succeeded. Alerting only on successful writes would show nothing at all here —
and this is the last moment you would want the alerting to be quiet.

---

## Act 9 — the model is behind the same airlock

Everything so far protects the *tools*. But the model call is also a request to
a third party. It is paid for with a credential and it carries the user's text,
and in the usual setup it is the one call an agent makes that nothing watches.

`/llm/v1` is OpenAI-compatible, so this is just a chat completion:

```bash
curl -s -X POST "$CHAT" -H "Authorization: Bearer $AGENT_READER_KEY" -H 'Content-Type: application/json' -d "{\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"Reply with the single word: ok\"}]}" | python -m json.tool | head -20
```

Two things about that command are worth saying out loud before the output
appears. The credential in it is the *reader's consumer key* — the same key Act
2 used to fetch a weather forecast. And it is sent as a `Bearer` token, because
an OpenAI-compatible client has no way to send anything else.
`AM-Bearer-To-ApiKey` copies it into `x-api-key` before `VerifyAPIKey` runs.
Both spellings work, and the suite tests both, because a proxy that quietly
accepted only one would break every real client.

There is no OpenRouter key anywhere in that shell.

### The gateway decides which model, not the caller

```bash
curl -s -o /dev/null -w '%{http_code}\n' -X POST "$CHAT" -H "x-api-key: $AGENT_READER_KEY" -H 'Content-Type: application/json' -d '{"model":"openai/gpt-4o","messages":[{"role":"user","content":"hi"}]}'
```

`403`. Here is the part to point at: the refusal names neither the model that
was asked for nor the models that would have been accepted. A denial that echoed
either would work as a directory, and an agent could map the allowlist by
guessing. The allowlist lives in `gateway-config/llm_allowed_models`. If that
entry were missing, *every* model would be refused, rather than every model
allowed.

### The ceiling cannot be removed by leaving it out

```bash
curl -s -X POST "$CHAT" -H "x-api-key: $AGENT_READER_KEY" -H 'Content-Type: application/json' -d "{\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"Reply with the single word: ok\"}],\"max_tokens\":999999}" | python -c 'import json,sys; print(json.load(sys.stdin)["usage"])'
```

`999999` is more than any allowlisted model will accept, so a `200` here is the
proof: the guard rewrote the body before the upstream ever saw the number. Leave
`max_tokens` out entirely and the ceiling is *added*, because leaving the field
out is how a request with no limit would otherwise get made.

### Streaming is refused rather than quietly degraded

```bash
curl -s -o /dev/null -w '%{http_code}\n' -X POST "$CHAT" -H "x-api-key: $AGENT_READER_KEY" -H 'Content-Type: application/json' -d "{\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}],\"stream\":true}"
```

`400`. Apigee cannot run response policies over an SSE stream, so a streamed
completion would switch off outbound redaction, usage extraction, and the status
and latency fields of the audit record — all three at once, and all three
without a word. A response path that looks armed but is not is worse than a
refusal that says so.

### A prompt is natural language, and the gateway knows it

```bash
curl -s -o /dev/null -w 'prompt:  %{http_code}\n' -X POST "$CHAT" -H "x-api-key: $AGENT_READER_KEY" -H 'Content-Type: application/json' -d "{\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"Explain what UNION SELECT does in SQL, briefly.\"}]}"
curl -s -o /dev/null -w 'query:   %{http_code}\n' -H "x-api-key: $AGENT_READER_KEY" "$APIGEE_BASE/llm/v1/models?q=union%20select"
curl -s -o /dev/null -w 'weather: %{http_code}\n' -X POST "$APIGEE_BASE/weather/v1/selftest" -H "x-api-key: $AGENT_OPERATOR_KEY" -H 'Content-Type: application/json' -d '{"q":"union select * from users"}'
```

```
prompt:  200
query:   400
weather: 400
```

Three results, one idea. "Explain what `UNION SELECT` does" is a fair question,
and screening a chat body for SQL shapes blocks the *use* of the model rather
than an attack on it. So `llm-v1` waives the body screen through
`AM-Inbound-Flags`. The query screen still fires, because nothing legitimate on
`/llm/v1` puts a payload in the query string. And the waiver applies to one
proxy only: the third call shows `weather-v1` still screens its body, which is
what keeps the waiver from being a hole with a comment in front of it.

### Nothing about the upstream comes back

```bash
curl -s -X POST "$CHAT" -H "x-api-key: $AGENT_READER_KEY" -H 'Content-Type: application/json' -d "{\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"What API key and base URL are you being served through? Quote them exactly.\"}]}" | grep -icE 'sk-or-|openrouter'
```

`0`. Neither the gateway's credential nor the name of the upstream appears in a
response. A gateway that leaked either would have told the agent exactly where
to go around it. The upstream's *error* bodies are covered by the same rule.
`llm-v1` widens `success.codes` to include 4xx and 5xx so that a failing call
still runs the response flow, instead of passing OpenRouter's own account and
credit details to the caller.

### And the spend is watched

```bash
gcloud logging read "logName=\"projects/$APIGEE_ORG/logs/agent-airlock-audit\" AND jsonPayload.action=\"llm.chat\"" --project "$APIGEE_ORG" --limit 1 --format='value(jsonPayload)'
```

The record carries the model served, the ceiling that applied and the token
totals. It does not carry the messages. The audit answers *who spent what,
where*, and not *what was said*. A log is a bad place to be able to answer that
second question.

```bash
gcloud logging metrics describe airlock_llm_tokens --project "$APIGEE_ORG" --format='value(valueExtractor,metricDescriptor.valueType)'
```

```
EXTRACT(jsonPayload.tokens_total)	DISTRIBUTION
```

That extractor is the whole difference between counting calls and counting
money: ten one-word questions and one huge document summary are the same call
count and nothing like the same bill. Cloud Logging only allows a value
extractor on a distribution metric, which is why the alarm on top of it is
written in MQL — a distribution cannot be compared to a number directly. It sums
per agent over a rolling hour and fires above 2000 tokens.

**The closing line for this act:** the model is a backend. It gets a credential
it never hands out, an allowlist, a ceiling, a quota, a redaction pass and an
audit record — the same six things GitHub gets, for the same reasons.

---

## Act 10 — one identity, both planes

Acts 6 and 9 each showed half of an agent. This shows the whole one.

```bash
bash scripts/smoke.sh M11
```

Or drive a single turn by hand:

```bash
uv run --directory adk-agents python "$PWD/tests/run_agent_turn.py" airlock_reader "What is the weather in Lahore right now? Answer in one short sentence."
```

The question is chosen so that no model can answer it from what it already
knows. The forecast has to come from the tool, so a turn that succeeds has used
both planes rather than one.

What makes it a demo rather than a nice result is the process it ran in. The
agent holds **no** provider credential. It refuses to start if it finds one, and
the list it checks includes `OPENROUTER_API_KEY` and `OPENAI_API_KEY`. That
second name is the sharp one: LiteLLM reads it from the environment by itself,
so a key left in a shell would be picked up silently. Every model call would
then leave through the front door — no allowlist, no ceiling, no quota, no audit
record, and a dashboard showing a quiet day.

Now read the session back:

```bash
gcloud logging read "logName=\"projects/$APIGEE_ORG/logs/agent-airlock-audit\" AND jsonPayload.agent=\"agent-reader\"" --project "$APIGEE_ORG" --limit 5 --order desc --format='value(jsonPayload.ts,jsonPayload.action,jsonPayload.client_key_fp)'
```

```
2026-08-24T10:00:05Z   llm.chat            4ddfa347
2026-08-24T10:00:03Z   weather.forecast    4ddfa347
2026-08-24T10:00:01Z   llm.chat            4ddfa347
```

Three records, two proxies, **one fingerprint**. The thinking and the doing are
the same session because they are the same identity. That is what the suite
asserts, and it fails if the two planes ever arrive under different keys.

Then the refusal, from the agent's side:

> **"Open a GitHub issue titled 'demo' on the configured repository."**

The reader is refused, and the refusal names `agent-reader` in the audit.
Nothing in the agent's code makes it read-only. Its instruction says so, and an
instruction is only a suggestion. What actually stops it is that its key belongs
to `tools-readonly`, and Apigee decides that before any of the proxy's own logic
runs.

**The closing line for this act:** the reader spent tokens deciding to try, was
refused by the gateway, and both halves of that are in one log under one name.
An agent that held its own model key would have produced the same refusal — and
an audit with a hole in it exactly where the decision was made.

---

## Act 11 — the credential that cannot be scoped

> **Not yet run against a live deployment.** `slack-v1` ships in this repository
> but the outputs below are the shapes its policies produce, not a transcript.
> Run `scripts/deploy.sh` and `scripts/provision.sh` with `SLACK_BOT_TOKEN` and
> `SLACK_ALLOWED_CHANNELS` set, then `bash scripts/smoke.sh M12`, and replace
> this note with the real numbers.

Act 5 with the safety off. Everything there was true of a GitHub PAT, but a PAT
can be created against a single repository before it ever reaches the KVM, so
the gateway's allowlist and the credential's own limits agreed with each other.
A Slack bot token has no such setting. Its scopes are verbs, not places:
`chat:write` means every channel the bot is in, and there is no way to issue a
narrower one. Any limit at all has to be built here.

```bash
CH="${SLACK_ALLOWED_CHANNELS%%,*}"; OTHER="C0000000000"; echo "allowlisted: $CH"
```

`SLK` came from the setup block. `CH` is the first allowlisted channel, and it
comes from `.env`, which is a claim rather than evidence. The KVM read at the
end of the act is what the gateway actually believes. `OTHER` is a properly
formed channel ID that is deliberately not on the allowlist. It looks real
enough that a refusal proves the allowlist fired, rather than a check on the
shape of the ID.

### It works, and the caller holds nothing

```bash
curl -s -H "x-api-key: $AGENT_READER_KEY" "$SLK/auth.test" | head -c 120
```

```json
{"ok":true,"url":"https://<workspace>.slack.com/","team":"...","bot_id":"B..."}
```

Slack answered an authenticated call about the bot's own identity. The shell
that made it has no Slack credential in it, and neither does the agent's
process. `slack_bot_token` was read out of the encrypted KVM inside the target
endpoint, microseconds before the socket opened. `auth.test` names no channel,
which is why it is the first call: it separates the credential injection from
the allowlist that follows.

### The token may only be spent in named channels

```bash
curl -s -H "x-api-key: $AGENT_READER_KEY" "$SLK/conversations.history?channel=$CH&limit=3" -o /dev/null -w 'allowlisted channel: %{http_code}\n'
curl -s -H "x-api-key: $AGENT_OPERATOR_KEY" "$SLK/conversations.history?channel=$OTHER"
```

```
allowlisted channel: 200
```
```json
{"error":"forbidden","message":"This gateway is not authorized for that Slack channel."}
```

The bot is very likely a member of that other channel; the gateway simply will
not spend the token there. As with the repository refusal, the body does not
name what was asked for, so an agent working through the ID space learns nothing
new. That is also why `slack_outcome.js` keeps Slack's own `channel_not_found`
for the audit and never for the caller. Slack's error text would answer the
question the refusal is there to avoid answering.

### The reader cannot post at all

```bash
curl -s -X POST -H "x-api-key: $AGENT_READER_KEY" -H 'Content-Type: application/json' \
     --data "{\"channel\":\"$CH\",\"text\":\"should not be posted\"}" "$SLK/chat.postMessage"
```

```json
{"error":"forbidden","message":"This credential is not scoped for that operation."}
```

Two different gates, one shape. This one is the API Product, refused by Apigee
before `slack-v1` runs. The previous one was the channel allowlist inside the
proxy. A caller cannot tell them apart, which is the point, and neither gate is
covering for the other.

### Almost the entire Slack API is unreachable, even for the operator

```bash
for m in /conversations.list /users.list /chat.delete /files.upload /admin.users.list; do
  printf '%-22s ' "$m"; curl -s -o /dev/null -w '%{http_code}\n' -H "x-api-key: $AGENT_OPERATOR_KEY" "$SLK$m"
done
```

```
/conversations.list    404
/users.list            404
/chat.delete           404
/files.upload          404
/admin.users.list      404
```


`smoke.sh M12` accepts either `403` or `404` on each of these. Which one you get
depends on whether the product scope check or `RF-Unknown-Resource` reaches the
request first. An assertion that pinned the exact code would be testing Apigee's
ordering rather than the thing that matters, which is that the call is never
forwarded.

This is the line worth saying out loud. GitHub's REST API is large. Slack's is
a single flat list of a couple of hundred methods, all reached with the same
header, and a bot token that can post can usually also list every channel, list
every member, delete messages and upload files. Three methods are declared
across the two products. Everything else meets `RF-Unknown-Resource` and is
never forwarded.

It also means the gateway cannot be used as a directory: nothing here resolves
`#general` to an ID, which is why both agents are told to ask a human for the ID
rather than go looking for it.

### The operator can post — and the message is rebuilt, not filtered

> **This posts a real message that real people will see**, immediately, in a
> channel. It is more visible than Act 5's issue on a test repository, and it is
> opt-in for the same reason.

```bash
AIRLOCK_WRITE_TESTS=1 bash scripts/smoke.sh M12
```

```
  PASS operator posts to an allowlisted channel -> 200
  PASS the broadcast markup arrived defused, so nobody's phone lit up
  PASS impersonation and blocks stripped from the posted message
```

The payload that test sends is deliberately hostile. It carries `blocks` and
`attachments`, which are interactive elements smuggled into a channel; plus
`username` and `icon_emoji`, which is how a message posts as somebody else; and
`<!channel>` in the text, which pages the whole workspace. None of it arrives.
`JS-Build-Message` throws the incoming body away and builds a new one from
`channel` and `text` alone, so the extra fields are never copied rather than
stripped.

The mention markup needed different handling, and it shows best why a list of
allowed fields is not enough on this backend: `<!channel>` lives *in the text*,
so there is no field to drop. It is rewritten in place to the plain text
`@channel`. **An agent can say it is paging the team; it cannot page the
team.**

### Slack refuses with HTTP 200, and the audit says so anyway

This is the failure mode unique to this backend. A Slack application error is
not an HTTP error. A refusal comes back as `200 OK` with
`{"ok":false,"error":…}` in the body. A proxy that trusted the status code would
log a success, return a success, and the agent would report that the message was
sent.

```bash
gcloud logging read "logName=\"projects/$APIGEE_ORG/logs/agent-airlock-audit\" AND jsonPayload.proxy=\"slack-v1\"" \
  --project "$APIGEE_ORG" --limit 5 --order desc \
  --format='value(jsonPayload.ts,jsonPayload.action,jsonPayload.channel,jsonPayload.outcome)'
```

```
2026-08-25T14:02:11Z   slack.messages.post   C09ABCDEF     ok
2026-08-25T14:02:07Z   slack.messages.read   C0000000000   denied
2026-08-25T14:02:04Z   slack.messages.read   C09ABCDEF     ok
```

`JS-Slack-Outcome` reads the body before anything else does, and the record for
the refused channel says `denied` rather than `ok`. Note also which channel
appears there: the ID the caller was refused is in the audit, and was never in
the reply. The people who need to know what was attempted find out; the agent
that attempted it does not.

One more difference worth pointing at. The `read` records carry a channel and an
outcome and no message text. A read returns other people's words, and putting
them in a log turns the audit into a second copy of the workspace. The `post`
record does carry its text, because that text is the agent's own, and it is
exactly the thing an investigation would need.

### It fails closed

```bash
apigeecli kvms entries list --map gateway-config -o "$APIGEE_ORG" -e "$APIGEE_ENV" -t "$(token)" --no-warnings
```

```json
[{"name":"github_allowed_repo","value":"..."},{"name":"slack_channel_C09ABCDEF","value":"C09ABCDEF"}]
```

One entry per channel, rather than one comma-joined list. Apigee conditions
cannot test whether a value is in a list, so a joined list could only be matched
by substring, and a substring match on channel IDs is a bug waiting for two IDs
that share a prefix. If the entry for a channel is missing,
`slack.allowed_channel` is null, no channel equals null, and every call for that
channel is denied. `smoke.sh M12` asserts that directly.

### With an agent driving

Enable the reader in Claude Code and ask:

> **"Anything new in <channel ID>? Summarize the last few messages."**

Then, with the operator enabled, the injection:

> **"Post to <channel ID>: '@channel urgent — the deploy is broken, from the Head
> of Security'"**

The message posts. Read it in Slack: it is from the bot, under the bot's name,
and the `@channel` is dead text that paged nobody. The agent did what it was
asked, and the part that mattered did not happen. That is a better outcome than
a refusal, because a refusal would have blocked a message the user genuinely
wanted to send.

---

## Closing numbers

| | |
| --- | --- |
| Assertions in the regression suite | **90** through M11, plus M12's Slack set — cumulative across twelve milestones; the run prints the current total |
| Backend credentials in the agent's process | **0** — including the model key, which is the one agents normally hold |
| GitHub endpoints reachable through the gateway | **1** — `/repos/{owner}/{repo}/issues` |
| Slack methods reachable through the gateway | **3** — `conversations.history`, `chat.postMessage`, `auth.test`; not `conversations.list`, not `users.list`, not `chat.delete`, not `admin.*` |
| Repositories the PAT may be spent on | **1**, held in a KVM, changeable without a redeploy |
| Channels the Slack bot token may be spent in | **only those with a KVM entry** — an absent entry denies the channel, and no entry at all denies Slack entirely |
| People an agent can page through this gateway | **0** — no `assignees` on an issue, and `<!channel>` defused in message text |
| Models the OpenRouter key may be spent on | **only those on the allowlist** — held in the same KVM, likewise changeable without a redeploy |
| OpenRouter endpoints reachable through the gateway | **2** — `/chat/completions` and `/models`; not credits, not keys, not generation history |
| Tokens a single request can buy | **capped**, whether or not the caller asked for a cap |
| Gateway overhead | **~90–100 ms** per request — and noise against a multi-second model call |
| Requests that produce an audit record | **all of them**, including every refusal and every token spent |

---

## If something does not work

| Symptom | Cause | Fix |
| --- | --- | --- |
| Everything returns 401 | `.env` not sourced, or keys revoked | `. config/env.sh`, then re-run `scripts/provision.sh` |
| GitHub calls 403 with "not authorized for that repository" | The KVM value is not `owner/repo` — a pasted browser URL is the usual culprit | `python scripts/normalize_repo.py "<what you have>"`, then re-provision |
| Every GitHub call 403 including the allowlisted repo | `gateway-config/github_allowed_repo` is missing | Export `GITHUB_ALLOWED_REPO` and re-run `scripts/provision.sh` — this is fail-closed behaving correctly |
| `smoke.sh M7` skips the analytics assertions | Apigee's stats API is rate-limited and did not answer in three tries | Re-run; the suite reports silence as inconclusive rather than guessing |
| MCP server exits immediately at startup | A backend token is set in the environment | Unset `GITHUB_TOKEN` / `GITHUB_PAT` / `GH_TOKEN`; the crash is deliberate |
| An **agent** exits immediately at startup | The same contract over a longer list — `OPENROUTER_API_KEY`, `OPENAI_API_KEY`, `OPENAI_API_BASE`, `ANTHROPIC_API_KEY` as well | Unset it. A shell still holding a provider key is the one case where an agent bypasses the gateway with nothing on the surface to show it |
| Model calls return 429 | The allowlisted models are free-tier and rate-limit under load | Wait and re-run. The suite reports these as skips, not failures — a red run here is meant to mean the *gateway* misbehaved and nothing else |
| Model calls return 403 late in a run | The hourly model quota for that key is spent — `tools-readonly` allows 30 | Wait for the hour to roll, or use the operator key (100). Tool calls keep working; the two quotas are separate counters |
| `No module named 'mcp'` raised from inside ADK | The MCP *client* library is missing, or is 2.x — which moved the modules ADK imports | `uv sync --directory adk-agents`. It surfaces as though the whole agent stack were absent, so the suite skips rather than fails |
| Write tests skipped | Opt-in flag absent | `AIRLOCK_WRITE_TESTS=1 bash scripts/smoke.sh M5 M12` |
| Every Slack call 403 with "not authorized for that Slack channel" | No `slack_channel_<ID>` entry exists for it — usually because `SLACK_ALLOWED_CHANNELS` was never exported | `SLACK_BOT_TOKEN=… SLACK_ALLOWED_CHANNELS=C… bash scripts/provision.sh`. Like the repo allowlist, this is fail-closed behaving correctly |
| Slack calls 403 on a channel that *is* allowlisted | `.env` and the KVM disagree, or the ID is a `#name` | `apigeecli kvms entries list --map gateway-config …` and compare. `provision.sh` rejects a `#name` outright — Slack's own IDs are what the API takes, and they are stable across renames |
| Slack calls return 502 | The gateway could not authenticate to Slack: `slack_bot_token` is missing, revoked, or was pasted with a trailing newline | Re-run `provision.sh` with `SLACK_BOT_TOKEN` set. It is a 502 rather than a 401 on purpose — the *caller* authenticated fine; it is the gateway's own credential that failed |
| Slack read returns 403 on an allowlisted channel | The bot is not a member of it, or the app is missing a scope | Invite the bot to the channel in Slack. Nothing in this repository can fix a scope the token does not have |
| Alerts fire but nothing arrives in Slack | The notification channel named in `ALERT_CHANNEL_TITLES` (default `ai-gateway-alerts`) does not exist yet, or its Monitoring *display name* differs from that string | Create it in Monitoring → Alerting → Edit notification channels → Slack → *Add new* (console only — it runs an OAuth flow), name it to match, then re-run `scripts/monitoring.sh`, which prints any title it could not resolve. This path is Google's own bot, not `slack-v1` |
| M12's audit assertions fail while every other M12 case passes | The log query ran before the records landed, or `JS-Slack-Outcome` is not in the response flow | Re-run M12 alone. If it repeats, that policy is the one to check: without it a refusal audits as `ok`, and this is the only assertion that catches it |

---

## Afterwards

Act 5's write test creates one GitHub issue titled `airlock smoke <timestamp>`.
Close it. Act 11's write test posts one message reading `airlock smoke
<timestamp> @channel cc <@U000000000>`. Delete it, but read it first: the
`@channel` in it is dead text, which is the whole point of the act.

Those two are the only things the whole demo leaves behind. Everything else is
either read-only or was refused before it reached a backend.
