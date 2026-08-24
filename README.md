# Agent Airlock — Apigee as an MCP gateway

An MCP server that holds no backend credentials. Every tool call leaves the
agent's machine as an ordinary HTTPS request to Apigee, which authenticates the
agent, checks what that identity is allowed to do, screens the payload, injects
the *real* backend credential from an encrypted KVM, calls the backend, and
redacts the response on the way out.

The point is where the trust boundary sits. A conventional MCP server is handed
a GitHub token and is then, by construction, exactly as privileged as that
token: a prompt injection that reaches it can spend the whole thing. Here the
token never exists on the agent's side of the wire. The blast radius of a fully
compromised agent is whatever Apigee's policies allow — currently: read weather,
and list or create issues on one named repository. Nothing else.

The same argument then runs a second time, against the credential agents
normally *do* hold. `proxies/llm-v1/` puts the model behind the identical
airlock: an agent's LLM client points at `/llm/v1`, presents the same consumer
key it uses for tools, and the OpenRouter key is injected from the same
encrypted KVM as the PAT. The model gets an allowlist, a token ceiling, its own
quota and an audit record — so the reasoning half of a session stops being the
part no log can see. `adk-agents/` holds two agents that work this way.

```
Claude Code ──stdio──> mcp-server/server.py ──HTTPS + x-api-key──> Apigee (eval org)
  or an ADK agent      (no backend creds)                          │
       │                                                           │
       └────HTTPS + Bearer <the same consumer key>───> /llm/v1 ────>│
                                                                   │
                                                                   ├─ VerifyAPIKey        identity
                                                                   ├─ API Product         scope
                                                                   ├─ SpikeArrest/Quota   rate
                                                                   ├─ JSONThreatProtection + injection screen
                                                                   ├─ KVM (encrypted)     credential injection
                                                                   ├─ repo allowlist / model allowlist
                                                                   ├─ token ceiling + per-product model quota
                                                                   └─ response redaction + fault sanitizing
                                                                   │
                                       api.open-meteo.com / api.github.com / openrouter.ai
```

## Layout

| Path | What |
| --- | --- |
| `proxies/weather-v1/` | Open-Meteo forecast + archive, no credential needed |
| `proxies/github-v1/` | GitHub issues; the PAT is fetched from a KVM at target time |
| `proxies/llm-v1/` | The model plane: OpenAI-compatible, model allowlist, token ceiling, its own quota |
| `resources/jsc/llm_guard.js` | Rewrites the chat body — allowlist, ceiling, routing fields stripped |
| `sharedflows/sf-inbound-security/` | API key, spike arrest, quota, threat protection, injection screen |
| `sharedflows/sf-outbound-redaction/` | Strips credential-shaped material from responses |
| `sharedflows/sf-fault-sanitizer/` | Every error becomes `{"error","message"}` — no Apigee internals |
| `sharedflows/sf-target-hygiene/` | Removes inbound auth headers before any upstream call |
| `sharedflows/sf-audit-build/` | Assembles the audit record — runs on the response *and* fault paths |
| `sharedflows/sf-audit-log/` | Writes that record to Cloud Logging from `PostClientFlow` |
| `config/products/` | API products — the scope model |
| `config/apps.json` | The two agent identities |
| `scripts/provision.sh` | Idempotent: products, apps, KVMs, keys into `.env` |
| `scripts/deploy.sh` | Bundles and deploys proxies and shared flows |
| `scripts/normalize_repo.py` | Reduces whatever a human supplied for the repo allowlist to `owner/repo`, or fails the run |
| `scripts/monitoring.sh` | Log-based metrics + alert policies: GitHub write attempts, and token spend per agent |
| `scripts/reports.sh` | The three Apigee Analytics views — traffic, errors, latency |
| `scripts/smoke.sh` | The acceptance suite. `M0`…`M11` filters, cumulative |
| `mcp-server/` | The stdio MCP server |
| `adk-agents/` | Two ADK agents whose model *and* tools both go through the gateway — see [its README](adk-agents/README.md) |
| `tests/` | pytest + node unit tests, driven by `smoke.sh` |
| `tests/run_agent_turn.py` | Drives one agent turn non-interactively; its exit codes separate "gateway broke" from "free tier was busy" |
| `tests/audit_replay.py` | Replays a scripted 10-call session back out of the audit log |
| `tests/latency_p95.py` | p95 latency per target, computed from the audit log |

## Identities

Two agents, two API keys, two API products. The split is the demo: the same
codebase, the same tools, different authority.

| | `agent-reader` (`tools-readonly`) | `agent-operator` (`tools-operator`) |
| --- | --- | --- |
| weather `/forecast` | GET | GET |
| weather `/archive`, `/selftest` | — | GET (+POST on selftest) |
| github issues | GET | GET, POST |
| llm `/chat/completions`, `/models` | POST, GET | POST, GET |
| tool quota | 100/hour | 100/hour |
| model quota | 30/hour | 100/hour |

Scope is enforced by the API Product, which Apigee evaluates in PreFlow — before
any of the proxy's own logic. A path that is not in the product returns 403
"not scoped" and never reaches the proxy at all. `tools-quotaprobe` (10/hour)
exists only so the quota tests can exhaust a budget cheaply — and it carries no
model operations at all, which is the cheapest possible demonstration that
reaching a model is a scoped privilege rather than something every key has.

The two quota rows are separate counters, not one budget split two ways: Apigee
scopes a quota to the policy that enforces it, so `Q-LLM-Quota` and `Q-Quota`
never share a bucket. That is what keeps a burst of forecast calls from
exhausting an agent's ability to think, and a runaway reasoning loop from
locking it out of its tools. The per-identity number comes from an `llm_quota`
attribute on the product, read by `countRef` — so changing what an agent may
spend is a product edit, not a proxy redeploy.

## Setup

Requires `gcloud` (authenticated against the Apigee org), `apigeecli` in
`~/bin`, `uv`, `node`, and bash. Infrastructure for the eval org — env group,
PSC NEG, external ALB, Google-managed cert on a `nip.io` hostname — is already
provisioned; `config/env.sh` carries the resulting host.

```bash
cp .env.example .env && bash scripts/deploy.sh && bash scripts/provision.sh
```

`provision.sh` writes the consumer keys into `.env`. It is idempotent — rerun it
whenever products or apps change.

### Supplying the GitHub credential

The PAT is never committed, never hardcoded, and never passed as a command-line
argument (argv is world-readable from the process table). `provision.sh` reads
it from the environment and pipes it to the Apigee control plane on stdin:

```bash
GITHUB_PAT='<your token>' GITHUB_ALLOWED_REPO='owner/repo' bash scripts/provision.sh
```

A fine-grained PAT scoped to that one repository with Issues read/write is
enough. Once it is in the KVM the value cannot be read back out — Apigee returns
it only to policies, and `KVM-Get-GitHub-PAT` writes it into a `private.*`
variable, which Apigee masks even in a debug trace.

`GITHUB_ALLOWED_REPO` goes into a separate, unencrypted `gateway-config` KVM.
The proxy compares the requested `owner/repo` against it and returns 403 for
anything else — without echoing back which repository was asked for, so the
error cannot be used to probe for private repositories.

That comparison is literal, against the two path segments the proxy lifted out
of the request, which makes the stored value load-bearing in a way its format
does not advertise. A pasted browser URL — the obvious thing to supply — becomes
a value no request can ever equal, and the refusal it produces reads
`not scoped for that operation`: a false lead pointing at the caller's API key
rather than at the allowlist. So the shape is settled at the moment a human
hands it over. `scripts/normalize_repo.py` reduces a github.com URL to
`owner/repo` and refuses anything that does not resolve to exactly one
repository, including URLs that point deeper than the repository root —
`/owner/repo/issues` could mean either the issues of `owner/repo` or a
repository named `issues`, and guessing is not a thing an allowlist should do.
A value that cannot be read is fatal to the run, because an allowlist nobody can
satisfy is not a safe default; it is a gateway that has quietly stopped working
while still reporting success.

The failure mode in the other direction is the dangerous one, and `smoke.sh M5`
asserts it in the only configuration where it is observable — before the KVM has
been provisioned at all. A missing entry leaves `gh.allowed_repo` null, and a
null comparison that came out *equal* would hand the stored PAT every repository
on GitHub. So an unprovisioned allowlist must deny, and the suite checks that it
does before it skips the tests that need a real repository. The suite reads the
KVM to decide whether those tests can run, rather than trusting the variable in
`.env` — what a local file says is not evidence about the gateway.

### Supplying the model credential

Same rules, same script:

```bash
OPENROUTER_API_KEY='<your key>' LLM_ALLOWED_MODELS='vendor/model-a,vendor/model-b' LLM_MAX_TOKENS=1024 bash scripts/provision.sh
```

The key goes into `backend-secrets` as `openrouter_api_key` and is injected by
`llm-v1` at target time, exactly as the PAT is. The other two go into the
unencrypted `gateway-config` KVM, because they are policy rather than secret and
are meant to be changed without touching a credential.

The two behave differently when missing, deliberately. An absent
`llm_allowed_models` denies **every** model — an allowlist nobody can satisfy is
the safe direction, and the same argument as the repo allowlist above. An absent
`llm_max_tokens` falls back to a built-in ceiling rather than to no ceiling,
because the failure it guards against is cost, and "unlimited" is not a
conservative reading of a missing number. Fail closed on access, fail safe on
spend.

The first entry in `LLM_ALLOWED_MODELS` is also what `adk-agents/` uses as its
default model, so the list is both the gate and the menu.

## Registering with Claude Code (Windows)

Both identities can be registered at once; the tool names collide, so in
practice enable one at a time, or keep only the reader enabled and turn on the
operator when a write is actually needed.

Add to `%USERPROFILE%\.claude.json` under `mcpServers` (or the project's
`.mcp.json`), substituting the keys from your `.env`:

```json
{
  "mcpServers": {
    "airlock-reader": {
      "command": "uv",
      "args": [
        "run",
        "--directory",
        "C:\\path\\to\\apigee-mcp-gateway\\mcp-server",
        "server.py"
      ],
      "env": {
        "APIGEE_HOST": "YOUR_LB_IP.nip.io",
        "AGENT_API_KEY": "<AGENT_READER_KEY from .env>",
        "AGENT_LABEL": "reader"
      }
    },
    "airlock-operator": {
      "command": "uv",
      "args": [
        "run",
        "--directory",
        "C:\\path\\to\\apigee-mcp-gateway\\mcp-server",
        "server.py"
      ],
      "env": {
        "APIGEE_HOST": "YOUR_LB_IP.nip.io",
        "AGENT_API_KEY": "<AGENT_OPERATOR_KEY from .env>",
        "AGENT_LABEL": "operator"
      }
    }
  }
}
```

`APIGEE_HOST` must be a bare hostname — the server refuses to start on a value
containing a scheme or a path, so configuration cannot silently redirect every
tool call somewhere else. It also refuses to start if `GITHUB_TOKEN`,
`GITHUB_PAT`, `GH_TOKEN`, `HA_TOKEN`, `HOME_ASSISTANT_TOKEN` or
`OPENWEATHER_API_KEY` is present in its environment: if a backend credential is
reachable from the agent's process, the airlock is already open, and crashing is
better than working.

Verify with the `whoami` tool — it reports the gateway and the identity label,
and never the key.

## Tests

```bash
bash scripts/smoke.sh
```

Cumulative: each milestone's tests keep running in every later one. Filter with
`scripts/smoke.sh M4`. Tests that need credentials skip with an explanation
rather than failing.

Issue creation is opt-in, because it is a real, visible side effect on someone's
repository rather than a test fixture:

```bash
AIRLOCK_WRITE_TESTS=1 bash scripts/smoke.sh M5
```

The MCP tests run inside the server's own virtualenv, since the `mcp` client
library is a dependency of the server rather than of this repository:

```bash
uv run --directory mcp-server --with pytest --with requests python -m pytest tests/test_mcp_server.py -q
```

## The audit trail

Every request through either proxy writes one JSON record to Cloud Logging, at
`projects/<org>/logs/agent-airlock-audit`. Refusals are recorded exactly like
successes — "what did the compromised agent *try* to do" is the question the log
exists to answer, and a log of only the calls that worked cannot answer it.

```json
{"ts":"2026-08-23T01:27:14.398Z","agent":"agent-reader","client_key_fp":"4ddfa347",
 "proxy":"weather-v1","revision":"18","verb":"GET","path":"/archive",
 "action":"weather.archive","status":403,"outcome":"denied",
 "fault":"InvalidApiKeyForGivenResource","latency_ms":47,
 "client_ip":"203.0.113.9","forwarded_for":"203.0.113.9, 198.51.100.5"}
```

The caller's API key is **fingerprinted, never logged**. Apigee exposes the key
as `client_id`, and logging that verbatim would make read access to the audit
equivalent to holding the key — so the record carries eight hex digits of an
FNV-1a hash instead. That is enough to group a caller's records and to match a
key you already hold against the log; it is not enough to reconstruct one.

The caller's address is recorded as a claim rather than a fact, because that is
what it is. The gateway sits behind an external ALB, so the only place the
caller's IP appears is `X-Forwarded-For` — and the ALB *appends* to that header
rather than replacing it, so the first element is the one hop a caller can write
themselves. `client_ip` is that first element; `forwarded_for` keeps the whole
chain, so the hops Google actually added are there to judge the claim against.

Reading that header is also the one thing in the audit that cannot be done where
the rest of the record is assembled. The builder runs in the response flow for a
served request, and by then `X-Forwarded-For` describes *Apigee's* call to the
backend, not the client's call to Apigee — so reading it there named a Google
front end as the caller on every request that succeeded, while refusals, built
during the request phase, were correct. A field that is right only on the
requests nobody investigates is worse than an absent one. `AM-Capture-Caller`
snapshots the header at the top of `sf-inbound-security`, ahead of the key check
so that an unauthenticated request is attributed too, and the builder reads the
snapshot.

Attribution has its own version of the same problem, and the sample record above
is what it looks like fixed. That refusal is an API Product scope refusal — a
real, registered key used for a resource it was not granted — and Apigee raises
it from inside `VerifyAPIKey`, before the policy has published anything. A debug
session over the whole transaction shows `developer.app.name`,
`verifyapikey.VA-VerifyAPIKey.app.name` and every other identity variable unset,
and the app's name appearing nowhere in the flow at all. So the record read
`"agent":"unauthenticated"` for a caller the gateway had recognised perfectly
well and merely refused — the opposite of what happened, on precisely the record
an investigation reaches for first. `AE-Resolve-App` looks the app up from the
consumer key directly, which is independent of `VerifyAPIKey` and so survives its
failure. It runs only when nothing else has produced a name, so a served request
never pays for it, and it resolves the *credential*, not the authorization: the
name says "this request carried the key registered to that app", and `outcome`
alongside it still says `denied`. A key registered to nothing resolves to
nothing, and that caller is correctly still `unauthenticated`.

That lookup came with a bill attached, which is worth stating because it is the
kind that usually goes unpaid. `AccessEntity` does not return a field, it returns
the whole app entity — and the whole app entity includes every consumer secret
the app holds, in plaintext, in a flow variable. Apigee masks `client_id` and
`access_token` in traces by default and knows nothing about that variable, so
until `scripts/provision.sh` added `AccessEntity.AE-Resolve-App` to the
environment's debug mask, anyone able to start a debug session could read the
credentials this gateway exists to keep out of reach. `EV-App-Name` lifts the one
attribute it needs and the rest is never logged; the mask is what stops it being
readable anyway. The mask lives on the environment rather than in a bundle,
because what may be observed here is a property of the environment, and because
it has to be in force before the proxy that needs it is deployed.

Nothing derived from a response body is ever logged, and the record is built
*after* the redaction pass, so it cannot describe a body the caller was not
allowed to see.

`scripts/monitoring.sh` builds the log-based metric `airlock_github_writes`
(issue-creation attempts, per agent, per outcome — refusals included) and an
alert policy that fires above 20 per agent per hour. Replay a session with:

```bash
uv run --directory mcp-server --with requests python ../tests/audit_replay.py
```

To prove the alert actually fires, drive the threshold with *denied* writes —
which is also the case worth alerting on, since a prompt-injected agent that
keeps retrying against policy looks exactly like this. Nothing is created on any
repository and the PAT is not needed:

```bash
for i in $(seq 1 25); do curl -s -o /dev/null -X POST -H "x-api-key: $AGENT_READER_KEY" -H 'Content-Type: application/json' -d '{"title":"alert drill"}' "$APIGEE_BASE/github/v1/repos/octocat/Hello-World/issues"; sleep 0.5; done
```

The `sleep` keeps it under the 10-per-second SpikeArrest, which would otherwise
convert the attempts into throttles and count them under a different outcome.
The metric aligns on a one-hour sum, so the incident lands a few minutes later
and auto-closes after 30.

## Analytics views

`scripts/reports.sh` creates three custom reports, idempotently — rerunning
updates them rather than piling up duplicates:

| View | Answers |
| --- | --- |
| requests per agent | is one identity suddenly doing far more than it used to |
| error rate per proxy | errors against total traffic, so the ratio is readable |
| latency per target | avg and max upstream time, plus total, per backend |

The gap between `total_response_time` and `target_response_time` is the airlock's
own cost — every policy in the chain, the key check, the KVM read, the redaction
pass. On this deployment it runs around **90–100ms** per request.

**p95 is not one of them, and that is a platform limitation rather than a
choice.** Apigee's stats API supports `sum`, `avg`, `min` and `max`; `p95(...)`
and `percentile95(...)` are both rejected as unsupported functions. Worse, the
custom-report API does not validate metric names at all — a report selecting
`p95_total_response_time` is created successfully and then renders nothing — so
"the report was created" proves only that a POST succeeded. So the percentile is
computed from the audit log, which has the per-request numbers to do it honestly:

```bash
python tests/latency_p95.py --hours 24
```

`smoke.sh M7` checks both halves of this: that each view's metric-and-dimension
pair actually returns rows from the stats API, and that `p95(...)` is *still*
rejected — so if Apigee ever grows a percentile function, the test fails and the
workaround can be deleted.

### Why the audit is split across two shared flows

`sf-audit-build` assembles the record; `sf-audit-log` writes it. They are
separate because **Apigee's `PostClientFlow` executes `MessageLogging` policies
and nothing else.** A `JavaScript` step placed there is reported in a debug
trace as having run successfully — `result: true`, execution time zero — while
setting no variables at all. The record came out empty and Cloud Logging
discarded the write, with every policy claiming success.

So the build runs where JavaScript actually executes — `PostFlow/Response` for a
served request, and both fault rules for a refused one, since a refusal
short-circuits straight past `PostFlow` — and only the write stays in
`PostClientFlow`, which is the one hook that runs unconditionally after the
response has reached the client. `tests/check_audit_wiring.py` asserts that
shape so it cannot quietly regress.

## What the tests are actually asserting

Not "does it work" so much as "does it still refuse":

- an unauthenticated call is refused, and the refusal names no Apigee internals
- the reader cannot POST an issue — refused at the product layer, before any
  repository check or KVM lookup runs
- the operator cannot reach `/user`, `/user/repos`, `/pulls`, or issue comments,
  even though the stored PAT would permit all of them
- a non-allowlisted repository is refused without the error echoing the target
- malformed or oversized issue payloads are rejected before the upstream call
- `assignees`, `labels` and `milestone` are stripped from a created issue: the
  gateway rebuilds the payload from an allowlist, so an agent cannot notify or
  tag people even though GitHub would happily accept those fields
- the audit records a refused call, not just a served one, and never contains
  the caller's API key in a spendable form
- the served and refused paths agree on who the caller was — the two records are
  assembled at different points in the flow, and comparing them is the only way
  to catch one of them silently recording the load balancer instead
- a call refused at the product scope still says which agent was refused — the
  fault means the key *was* recognised, so a record claiming the caller was
  unauthenticated is disclaiming knowledge the gateway has
- the app lookup's output variable is in the environment's debug mask — it carries the app's consumer secrets, and a trace is an operational surface like any other
- no GitHub token literal appears anywhere in tracked files
- the MCP server dies with exit 2 if a backend credential is in its environment

## Threat model

Each row names the mechanism and the test that would fail if it stopped working.
Nothing here is asserted on inspection alone.

| Threat | Mitigation | Verified by |
| --- | --- | --- |
| The MCP server's config is stolen | Only an Apigee consumer key is there to steal. It is scoped by API Product, revocable in one call, and buys nothing beyond the tools. Backend secrets are in an encrypted KVM the agent's side of the wire never touches. | `no agent key baked into server.py`, `no GitHub token literal in tracked files`, `live PAT absent from committable files`, and the startup guards in `test_mcp_server.py` — the server exits 2 if a backend credential is in its environment |
| An agent loops, or is driven to | SpikeArrest smooths bursts; a per-app Quota caps the hour. Both live in `sf-inbound-security`, so every proxy gets them by construction. | `pytest -k traffic` |
| A prompt injection reaches the agent and asks for something destructive | Three independent limits: the API Product decides which verbs an identity has, the proxy allowlists paths and refuses anything unmatched, and the repo allowlist decides where the PAT may be spent. None substitutes for the others. | `reader cannot POST an issue -> 403 scope`, `operator blocked from <path>` (one case per forbidden GitHub path), `non-allowlisted repo -> 403 without echoing the target`, `assignees stripped from the created issue` |
| A secret leaks back into the agent's context | The redaction shared flow drops credential-shaped keys and masks addresses on the way out; the fault sanitizer means an error cannot leak internals either. | `redact.js unit tests`, `no credential material in the GitHub response`, `emails masked in structured and free-text fields`, `fault body free of Apigee internals` |
| An agent acts and nobody can tell | One JSON record per request, refusals included, written from `PostClientFlow` so no early exit can skip it — plus a metric and an alert on write attempts. | `every call reaches Cloud Logging with its agent identity`, `a refused call is audited as denied`, `audit is built on the response and fault paths, written in PostClientFlow`, `tests/audit_replay.py` |
| The audit itself becomes the leak | The caller's key is fingerprinted, never recorded; nothing derived from a response body is logged; the record is built after redaction. | `the audit carries no credential`, `the caller key is fingerprinted, never recorded`, `no response-derived field ever appears in the record` |
| A malformed or oversized payload attacks a policy or a backend | JSONThreatProtection bounds depth and entry count; a regex screen rejects classic injection strings; the issue body is rebuilt from an allowlist rather than forwarded. | `50-deep JSON body -> 400 bad_request`, `malformed issue payload rejected before upstream`, `github_issue.js unit tests` |

The row the design actually rests on is the first one. Everything else limits what
a compromised agent can do; that row is why compromising the agent does not hand
anyone a GitHub token in the first place.

## Deviations from the spec

- **Home Assistant is dropped.** GitHub takes its place as the credential-
  injection backend in M5 and supplies the write-capable tools in M6, so the
  tools are `gh_list_issues` / `gh_create_issue` rather than `ha_get_states` /
  `ha_call_service`.
- Developer email is `agents@agent-airlock.example.com`; Apigee rejects
  `agents@local`.
- **p95 latency is computed outside Apigee.** The spec asks for "p95 latency
  per target" as an Analytics view; Apigee has no percentile function, so the
  Analytics view carries avg and max and `tests/latency_p95.py` computes the
  percentile from the audit log instead.
- The quota test uses a dedicated 10/hour product on a throwaway app instead of
  driving the 101st request through a 100/hour one — same assertion, two orders
  of magnitude less traffic.
