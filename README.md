# Apigee as an MCP and LLM gateway

Apigee sits in front of both halves of what an agent touches: the tools it
calls and the model that decides to call them. An MCP server holds no backend
credentials, and an LLM client holds no model credential either — every tool
call and every model call leaves the agent's machine as an ordinary HTTPS
request to Apigee, which authenticates the agent, checks what that identity is
allowed to do, screens the payload, injects the *real* backend credential from
an encrypted KVM, calls the backend, and redacts the response on the way out.

The point is where the trust boundary sits. A conventional MCP server is handed
a GitHub token and is then, by construction, exactly as privileged as that
token: a prompt injection that reaches it can spend the whole thing. Here the
token never exists on the agent's side of the wire. The blast radius of a fully
compromised agent is whatever Apigee's policies allow — currently: list or
create issues on one named repository, and read or post messages in one named
set of Slack channels. Nothing else.

Slack is where that argument gets its sharpest test, because a Slack bot token is
the least containable credential of the three. GitHub's PAT can be fine-grained
down to one repository before it ever reaches the KVM; Slack's cannot. A bot
token is scope-shaped, not resource-shaped — `chat:write` means every channel the
bot is in, and the Web API is one flat namespace of a couple of hundred methods
reachable with the same token. Confining it is therefore entirely the gateway's
job: three methods appear in the products, and one KVM entry per channel decides
where the token may be spent.

The same argument then runs a second time, against the credential agents
normally *do* hold. `proxies/llm-v1/` puts the model behind the identical
airlock: an agent's LLM client points at `/llm/v1`, presents the same consumer
key it uses for tools, and the OpenRouter key is injected from the same
encrypted KVM as the PAT. The model gets an allowlist, a token ceiling, its own
quota and an audit record — so the reasoning half of a session stops being the
part no log can see. `adk-agents/` holds two agents that work this way.

```
MCP Client ──stdio──> mcp-server/server.py ──HTTPS + x-api-key──> Apigee (eval org)
  or an ADK agent      (no backend creds)                          │
       │                                                           │
       └────HTTPS + Bearer <the same consumer key>───> /llm/v1 ────>│
                                                                   │
                                                                   ├─ VerifyAPIKey        identity
                                                                   ├─ API Product         scope
                                                                   ├─ SpikeArrest/Quota   rate
                                                                   ├─ JSONThreatProtection + injection screen
                                                                   ├─ KVM (encrypted)     credential injection
                                                                   ├─ repo / channel / model allowlists
                                                                   ├─ token ceiling + per-product model quota
                                                                   └─ response redaction + fault sanitizing
                                                                   │
                                      api.github.com / slack.com / openrouter.ai
```

## Layout

| Path | What |
| --- | --- |
| `proxies/github-v1/` | GitHub issues; the PAT is fetched from a KVM at target time |
| `proxies/slack-v1/` | Slack messages; the bot token is fetched from a KVM at target time, and a per-channel allowlist decides where it may be spent |
| `proxies/llm-v1/` | The model plane: OpenAI-compatible, model allowlist, token ceiling, its own quota |
| `shared/js/slack_message.js` | Rebuilds a post from `{channel, text}` alone and defuses `@channel`-style mention markup |
| `shared/js/slack_outcome.js` | Turns Slack's `HTTP 200 + {"ok":false}` into a real status, without echoing Slack's error string |
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
| `scripts/monitoring.sh` | Log-based metrics + alert policies: GitHub write attempts, and token spend per agent — both routed to a Slack channel the gateway cannot write to |
| `scripts/reports.sh` | The three Apigee Analytics views — traffic, errors, latency |
| `scripts/smoke.sh` | The acceptance suite. `M0`…`M12` filters, cumulative |
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
| github issues | GET | GET, POST |
| slack `/conversations.history`, `/auth.test` | GET | GET |
| slack `/chat.postMessage` | — | POST |
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
never share a bucket. That is what keeps a burst of tool calls from
exhausting an agent's ability to think, and a runaway reasoning loop from
locking it out of its tools. The per-identity number comes from an `llm_quota`
attribute on the product, read by `countRef` — so changing what an agent may
spend is a product edit, not a proxy redeploy.

## Prerequisites

Nothing here is exotic, but the list is not short, and every item on it is
load-bearing: the failure modes of a half-satisfied prerequisite are the
expensive kind, where a script exits 0 and the gateway quietly does not work.

**On the machine**

| | Why |
| --- | --- |
| `bash` | Every script is bash. On Windows use Git Bash or WSL — but pick one and stay in it, because `gcloud` credentials live per shell environment and a login done in one is invisible to the other |
| `gcloud`, authenticated | The control-plane token for every Apigee and Monitoring call: `gcloud auth login && gcloud config set project <org>` |
| `apigeecli` on `PATH` | Bundles, imports and deploys. `config/env.sh` prepends `~/bin`, which is where the installer puts it |
| `python` on `PATH` | Response parsing inside the scripts, plus `normalize_repo.py` |
| `node` | The `redact.js` and `slack_message.js` unit tests. Absent, those tests skip rather than fail |
| `uv` | Runs the MCP server and the ADK agents in their own virtualenvs |
| `curl` | KVM writes go to the control plane over `curl` with the value on stdin, never in argv |

**In Google Cloud**

An Apigee X organization — the eval tier is enough for all of this — with an
environment and an environment group, and a reachable ingress in front of it: an
external ALB with a Google-managed certificate, pointed at the Apigee runtime
through a PSC/serverless NEG. `nip.io` supplies the resolvable hostname the
certificate needs when you do not own a domain. Section 3 of
[ARCHITECTURE.md](ARCHITECTURE.md) draws the topology. Enable
`apigee.googleapis.com`, `logging.googleapis.com` and
`monitoring.googleapis.com` on the project — the scripts do not enable APIs for
you. The account running them also needs to create a service account and set
project IAM policy, because `provision.sh` creates the audit logger identity and
grants it `roles/logging.logWriter`.

**Credentials to have ready.** Each is pushed into an encrypted KVM by
`provision.sh`, and none is committed, logged, or passed in argv:

- A **GitHub fine-grained PAT** scoped to exactly one repository, Issues
  read/write. Fine-grained rather than classic, so the token and the gateway's
  allowlist agree about the blast radius.
- A **Slack bot token** (`xoxb-…`) from an app in your workspace, carrying the
  `chat:write` and `channels:history` scopes. Add the scopes *and then reinstall
  the app* — Slack does not retrofit a scope onto an already-issued token, and
  the symptom is an `M12` failure that reads like a gateway bug. Invite the bot
  to each channel you intend to allowlist, and collect the channel **IDs**
  (`C…`), not the names.
- An **OpenRouter API key**, plus the model IDs the gateway may spend it on.
  Free-tier IDs are fine and are what the tests assume.

## Setup

Copy the environment file and point it at your own org. The committed defaults
are this deployment's, and `config/env.sh` falls back to them for anything `.env`
leaves unset — so an unedited file will cheerfully deploy nowhere useful:

```bash
cp .env.example .env
```

Set `APIGEE_ORG`, `APIGEE_ENV`, `APIGEE_ENVGROUP` and `APIGEE_HOST`.
`APIGEE_HOST` is a bare hostname — no scheme, no path; the MCP server refuses to
start on anything else, so a config file cannot silently redirect every call.

Then provision, supplying the backend credentials in the same run:

```bash
GITHUB_PAT='<pat>' GITHUB_ALLOWED_REPO='owner/repo' SLACK_BOT_TOKEN='xoxb-...' SLACK_ALLOWED_CHANNELS='C09ABCDEF' OPENROUTER_API_KEY='<key>' LLM_ALLOWED_MODELS='vendor/model:free' bash scripts/provision.sh
```

```bash
bash scripts/deploy.sh
```

**Provision before deploy on a fresh org.** `provision.sh` creates the
`apigee-airlock-logger` service account; `deploy.sh` attaches that identity to
every bundle with `-s`. Deploying first means deploying against a service
account that does not exist yet. Either order works on every later run — both
scripts are idempotent. Rerun `provision.sh` whenever products, apps, KVM values
or allowlists change, and `deploy.sh` whenever a policy changes.

`provision.sh` writes the resulting consumer keys back into `.env` — keys only,
never secrets. Each credential above is independent: the script writes only the
KVM entries whose variables are set, and tests for anything unprovisioned skip
with a reason rather than failing.

Then wire the alarms and confirm the whole thing:

```bash
bash scripts/monitoring.sh
```

```bash
bash scripts/smoke.sh
```

`monitoring.sh` needs one thing done by hand first — a Slack notification
channel created in the Monitoring console, described under
[the audit trail](#the-audit-trail). Without it the metrics and policies are
still created; they just have nowhere to ring.

`smoke.sh` is the gate. A green run is the evidence that the gateway enforces
what this README claims, as opposed to the scripts having reported success.

### When `smoke.sh` reports a security failure

Check `gcloud` before anything else:

```bash
gcloud auth list && gcloud config get-value project
```

The suite reads the live KVM to decide which tests can run, on the principle
that what a local `.env` says is not evidence about the gateway. An
unauthenticated shell turns that read into a `401`, the pre-check reads `401` as
*"the allowlist was never provisioned"*, and a correct `200` on a genuinely
allowlisted channel is then reported as a gateway that admitted an unprovisioned
request. The alarm is real; the diagnosis is inverted. An `(unset)` account
here — easy to reach by running the suite from a different shell than the one
you provisioned from — is the cause, and the gateway is fine.

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

### Supplying the Slack credential

Same rules again, and the same script:

```bash
SLACK_BOT_TOKEN='<xoxb-...>' SLACK_ALLOWED_CHANNELS='C09ABCDEF,C09GHIJKL' bash scripts/provision.sh
```

The token goes into `backend-secrets` as `slack_bot_token`, read by
`KVM-Get-Slack-Token` into a `private.*` variable and injected at target time.
The channels go into `gateway-config` — but as **one entry per channel**,
`slack_channel_<ID>`, rather than one comma-joined list. That is not a style
choice: Apigee conditions have no list-membership operator, so a single entry
could only be compared with `=` and every allowlist beyond the first channel
would silently deny. The proxy builds the key from the requested channel and asks
the KVM whether that entry exists; a channel nobody provisioned leaves the
comparison variable null, and nothing equals null, so the default is denial.

Channels are named by **ID** (`C…`), never by `#name`. Resolving a name means
calling `conversations.list`, and a gateway that can enumerate a workspace's
channels has already granted the read the allowlist exists to withhold — so no
tool here can list channels, and both agents are told to ask the human for an ID
rather than guess one. A guess costs the user a turn and produces a logged
attempt against the allowlist, which is indistinguishable from enumeration at the
point where somebody is reading the alert.

The refusal is deliberately uninformative: 403 `not authorized for that Slack
channel`, with the requested ID absent from the body. Slack's own errors would
have given that away — `channel_not_found` versus `not_in_channel` tells a caller
whether a channel it guessed at exists — which is why `slack_outcome.js` keeps
Slack's error string for the audit and never for the caller.

Two things about the Slack API make the write path more than a proxy pass-through:

- **Slack refuses with HTTP 200.** An application error arrives as
  `200 {"ok":false,"error":"missing_scope"}`. Left alone, the audit would record
  `outcome: ok` on a call that did nothing, every alert would undercount, and the
  agent would be told its message was posted. `JS-Slack-Outcome` rewrites the
  status from the body before either the caller or the audit sees it.
- **A message body is a capability.** Slack would accept `blocks` and
  `attachments` (interactive elements posted into a channel), `username` and
  `icon_emoji` (posting as somebody else), and mention markup — `<!channel>`,
  `<!here>`, `<@U…>` — which pages real people straight out of the message
  *text*, with no separate field to strip. So `slack_message.js` rebuilds the
  request from `{channel, text}` alone and defuses the markup in the text itself.
  This is the same argument as `assignees` on a GitHub issue, one notch louder.

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
        "APIGEE_HOST": "apigee-airlock-eval.nip.io",
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
        "APIGEE_HOST": "apigee-airlock-eval.nip.io",
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
`GITHUB_PAT`, `GH_TOKEN`, `HA_TOKEN`, `HOME_ASSISTANT_TOKEN`,
`OPENWEATHER_API_KEY`, `SLACK_BOT_TOKEN`, `SLACK_USER_TOKEN`,
`SLACK_APP_TOKEN` or `SLACK_WEBHOOK_URL` is present in its environment: if a
backend credential is reachable from the agent's process, the airlock is already
open, and crashing is better than working. The webhook URL is on that list even
though it is not a token — it is a bearer capability in URL clothing, and an
agent holding one can post to a channel with no gateway in the path at all.

Verify with the `whoami` tool — it reports the gateway and the identity label,
and never the key.

## Tests

```bash
bash scripts/smoke.sh
```

Cumulative: each milestone's tests keep running in every later one. Filter with
`scripts/smoke.sh M4`. Tests that need credentials skip with an explanation
rather than failing.

Writes are opt-in, because they are real, visible side effects rather than test
fixtures — an issue on someone's repository, and a message every human in a Slack
channel sees the moment it lands:

```bash
AIRLOCK_WRITE_TESTS=1 bash scripts/smoke.sh M5 M12
```

`M12` covers Slack. The posted test message deliberately carries `<!channel>`,
`blocks` and `username`, and the assertion is on what comes back: the broadcast
markup arrives defused as `@channel`, and the other two fields are gone.

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
 "proxy":"github-v1","revision":"18","verb":"POST",
 "path":"/repos/your-org/your-repo/issues","action":"github.issues.create",
 "status":403,"outcome":"denied",
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
alert policy that fires above 20 per agent per hour.

A third metric, `airlock_denied_actions`, counts every call the gateway did
*not* serve, labelled with the agent, the action, the verdict and the name of
the policy that refused. Its alert policy is the one that answers “did an agent
do something it is not allowed to do?”, and its threshold is zero: a single 403
means an agent reached for a repository, a Slack channel or a model outside its
allowlist, and there is no number of those per hour that is normal. A second
condition on the same policy watches for a *burst* of 401s and other 4xx from
one identity — ordinary client breakage produces a steady trickle and
deliberately does not fire, while credential-guessing and a retry storm produce
a spike. Throttling is counted by the metric but alarmed on by neither
condition: a throttled agent is one the quota is already handling, and the
quota has its own alarm.

Running `scripts/smoke.sh` fires the refusal alarm, because M4, M5 and M12
provoke real 403s and the alarm's threshold is zero. That is correct behaviour
and on a first run it is worth watching arrive in Slack. To run the suite
quietly, set `AIRLOCK_SNOOZE_ALERTS=1`: it snoozes that one policy for the
length of the run (`AIRLOCK_SNOOZE_MINUTES`, default 30) and the snooze expires
by itself, so an interrupted run cannot leave the alarm off.

All three alarms — the write burst, the model spend and the refusal — fan out to every channel
named in `ALERT_CHANNEL_TITLES`, which defaults to the single Slack channel
`ai-gateway-alerts`. Slack is where these get *seen*, since a burst of denied
writes is something somebody should look at within minutes. It is also, by
default, the only delivery path, which is a real cost worth naming: a workspace
can be left, archived or rate-limited, and one path is one point of silence. Add
an email channel to the list if that matters more to you than the noise.

The value is matched **literally against the channel's Monitoring display name**,
which is not the same string as the Slack channel it posts to — they coincide
here only because the console seeds one from the other. Renaming either side
unwires the alarms.

**Create the channel before running the script.** `monitoring.sh` looks channels
up and never creates one — not because it cannot, but because the only token it
could create one with is the same bot token the gateway injects from the KVM,
and copying a credential into a second system doubles both the blast radius and
the number of places a rotation has to reach. Monitoring console → Alerting →
Edit notification channels → Slack → *Add new* runs Google's own OAuth flow,
mints a token belonging to Google's Slack app, and invites its bot to the
channel. Name it to match `ALERT_CHANNEL_TITLES` and rerun the script; a name it
cannot resolve is printed and skipped rather than silently dropped, because an
alert policy that quietly ends up with no channels still shows as healthy.

Point it at an alert channel the gateway is *not* allowlisted for. Alerting
about an agent through a channel that agent can write to is a loop worth not
building.

Note that this path is Google's own bot posting to Slack, not the gateway's — the
alerting stack does not go through `slack-v1`, and deliberately so. An alarm that
depends on the thing it is watching is not an alarm.

Replay a session with:

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
- no Slack token literal either, and no tool can list or resolve channels — the
  gateway has no way to enumerate a workspace even for the operator
- the reader cannot post a Slack message, and the operator cannot post to a
  channel outside the allowlist — two independent gates, tested separately
- a Slack refusal does not echo the channel that was asked for, and the two 403
  shapes (`channel_not_found`, `not_in_channel`) are byte-identical to the caller
- Slack's `HTTP 200 + {"ok":false}` becomes a real failure status before the
  audit sees it, so a refused call is never recorded as `outcome: ok`
- a Slack *read* carries no message text into the audit — `conversations.history`
  returns other people's messages, and the log records that a read happened,
  never what was read

## Threat model

Each row names the mechanism and the test that would fail if it stopped working.
Nothing here is asserted on inspection alone.

| Threat | Mitigation | Verified by |
| --- | --- | --- |
| The MCP server's config is stolen | Only an Apigee consumer key is there to steal. It is scoped by API Product, revocable in one call, and buys nothing beyond the tools. Backend secrets are in an encrypted KVM the agent's side of the wire never touches. | `no agent key baked into server.py`, `no GitHub token literal in tracked files`, `no Slack token literal in tracked files`, `live PAT absent from committable files`, `live Slack token absent from committable files`, and the startup guards in `test_mcp_server.py` — the server exits 2 if a backend credential is in its environment |
| An agent loops, or is driven to | SpikeArrest smooths bursts; a per-app Quota caps the hour. Both live in `sf-inbound-security`, so every proxy gets them by construction. | `pytest -k traffic` |
| A prompt injection reaches the agent and asks for something destructive | Three independent limits: the API Product decides which verbs an identity has, the proxy allowlists paths and refuses anything unmatched, and the repo/channel allowlist decides where the stored credential may be spent. None substitutes for the others. | `reader cannot POST an issue -> 403 scope`, `operator blocked from <path>` (one case per forbidden GitHub path and Slack method), `non-allowlisted repo -> 403 without echoing the target`, `non-allowlisted channel -> 403 on GET/POST without echoing it`, `assignees stripped from the created issue` |
| An injected agent uses a legitimate write to reach people | A Slack post is rebuilt from `{channel, text}` alone, so `blocks`, `attachments`, `username` and `icon_emoji` never reach Slack — an agent cannot post as somebody else or ship interactive elements into a channel. Mention markup lives in the message *text*, where there is no field to strip, so it is defused in place: `<!channel>` becomes `@channel` and stops paging anyone. | `slack_message.js` unit tests (20 cases), `the broadcast markup arrived defused, so nobody's phone lit up`, `impersonation and blocks stripped from the posted message` |
| A backend refuses, and the gateway records success | Slack answers application errors with `HTTP 200 + {"ok":false,"error":…}`. `JS-Slack-Outcome` rewrites the status from the body before the caller or the audit sees it, and keeps Slack's own error string for the audit only. | `slack_outcome.js` unit tests (15 cases), `a channel refusal is audited as denied`, `Slack's error string never reaches the caller` |
| The gateway itself becomes a discovery tool | No tool and no product entry can list channels, repositories or users. A refusal names nothing it was asked about, so walking the ID space yields identical errors and no map. | `no tool can list or resolve slack channels`, `operator blocked from /conversations.list`, `the two 403 shapes are indistinguishable to the caller` |
| A secret leaks back into the agent's context | The redaction shared flow drops credential-shaped keys and masks addresses on the way out; the fault sanitizer means an error cannot leak internals either. | `redact.js unit tests`, `no credential material in the GitHub response`, `emails masked in structured and free-text fields`, `fault body free of Apigee internals` |
| An agent acts and nobody can tell | One JSON record per request, refusals included, written from `PostClientFlow` so no early exit can skip it — plus a metric and an alert on write attempts. | `every call reaches Cloud Logging with its agent identity`, `a refused call is audited as denied`, `audit is built on the response and fault paths, written in PostClientFlow`, `tests/audit_replay.py` |
| The audit itself becomes the leak | The caller's key is fingerprinted, never recorded; nothing derived from a response body is logged; the record is built after redaction. Reads are asymmetric with writes on purpose — a Slack read returns other people's messages, so the record says a read happened and never what was read, while a post records the text the agent chose to send. | `the audit carries no credential`, `the caller key is fingerprinted, never recorded`, `no response-derived field ever appears in the record`, `a slack read carries no message text` |
| A malformed or oversized payload attacks a policy or a backend | JSONThreatProtection bounds depth and entry count; a regex screen rejects classic injection strings; the issue body is rebuilt from an allowlist rather than forwarded. | `50-deep JSON body -> 400 bad_request`, `malformed issue payload rejected before upstream`, `github_issue.js unit tests` |

The row the design actually rests on is the first one. Everything else limits what
a compromised agent can do; that row is why compromising the agent does not hand
anyone a GitHub token in the first place.

