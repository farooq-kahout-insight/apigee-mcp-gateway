# Apigee as an MCP and LLM gateway

## What this repo deploys

This repo sets up a small but complete working example. An AI agent does real
work, and Apigee sits in front of everything it touches.

- **An MCP server** that runs on your own machine and gives the agent its
  tools: list and create GitHub issues, read and post Slack messages. It holds
  no GitHub token, no Slack token, and no other backend credential.
- **An LLM endpoint** the agent uses as its model: `/llm/v1` on the same
  gateway. It is OpenAI-compatible and backed by OpenRouter. The agent sends
  the same key it uses for tools. The two Google ADK agents in `adk-agents/`
  are already set up this way.
- **Apigee in between.** Every tool call and every model call leaves the
  agent's machine as an ordinary HTTPS request to Apigee. Apigee checks who the
  agent is, checks what that agent is allowed to do, screens the payload, adds
  the real backend credential from an encrypted KVM, calls the backend (GitHub,
  Slack, or OpenRouter), and strips sensitive data out of the response.

The repo also ships what you need to run it: two agent identities with
different permissions, provisioning and deploy scripts, an audit log of every
request, monitoring alarms, and a smoke-test suite that checks each control by
trying to break it.

## Why it is deployed this way

It comes down to where the credentials live.

A normal MCP server is given a GitHub token, so it can do anything that token
can do. If a prompt injection reaches it, the attacker gets the whole token.
Here the token never reaches the agent's side of the wire. Even if an attacker
takes full control of the agent, they can only do what Apigee allows: list or
create issues on one named repository, and read or post messages in one named
set of Slack channels. Nothing else.

Slack is the hardest of the three to protect, because a Slack bot token is the
hardest kind of credential to limit. A GitHub PAT can be locked to a single
repository before it ever goes into the KVM. A Slack token cannot. Slack tokens
grant capabilities rather than access to specific resources: `chat:write` means
every channel the bot has joined, and the Slack Web API is one flat list of a
couple of hundred methods that all accept the same token. Limiting it is
therefore entirely the gateway's job. Only three methods appear in the API
products, and one KVM entry per channel decides where the token may be used.

The same idea then applies a second time, to the one credential agents usually
do hold: the model key. `proxies/llm-v1/` puts the model behind the same
gateway. The agent's LLM client points at `/llm/v1` and sends the same consumer
key it uses for tools, and the OpenRouter key is added from the same encrypted
KVM as the PAT. The model gets an allowlist, a token limit, its own quota, and
an audit record. That way the reasoning half of a session is logged too,
instead of being the part no log can see. `adk-agents/` holds two agents that
work this way.


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
| `proxies/weather-v1/` | The same policy chain against a public backend — no credential in play, so a green run here isolates the gateway from the upstreams |
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

Two agents, two API keys, two API products. Same code and same tools — only
the permissions differ. That difference is what the demo shows.

| | `agent-reader` (`tools-readonly`) | `agent-operator` (`tools-operator`) |
| --- | --- | --- |
| github issues | GET | GET, POST |
| slack `/conversations.history`, `/auth.test` | GET | GET |
| slack `/chat.postMessage` | — | POST |
| llm `/chat/completions`, `/models` | POST, GET | POST, GET |
| tool quota | 100/hour | 100/hour |
| model quota | 30/hour | 100/hour |

Scope is enforced by the API Product. Apigee checks it in PreFlow, before any
of the proxy's own logic runs. A path that is not in the product returns 403
"not scoped" and never reaches the proxy at all. `tools-quotaprobe` (10/hour)
exists only so the quota tests can use up a budget cheaply. It carries no model
operations at all, which is the simplest way to show that reaching a model is a
permission an agent has to be granted, not something every key has.

The two quota rows are separate counters, not one budget shared between two
things. Apigee ties a quota to the policy that enforces it, so `Q-LLM-Quota`
and `Q-Quota` never draw from the same bucket. That keeps a burst of tool calls
from using up an agent's ability to think, and a runaway reasoning loop from
locking it out of its tools. The per-identity number comes from an `llm_quota`
attribute on the product, read by `countRef`, so changing what an agent may
spend is an edit to the product, not a proxy redeploy.

## Prerequisites

None of this is unusual, but the list is long and every item on it matters.
A half-finished prerequisite fails in the expensive way: the script exits 0 and
the gateway quietly does not work.

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

You need an Apigee X organization (the eval tier is enough for all of this)
with an environment and an environment group, plus a way to reach it from the
internet: an external ALB with a Google-managed certificate, pointed at the
Apigee runtime through a PSC/serverless NEG. If you do not own a domain,
`nip.io` gives you the resolvable hostname the certificate needs. Section 3 of
[ARCHITECTURE.md](ARCHITECTURE.md) draws the topology.

Enable `apigee.googleapis.com`, `logging.googleapis.com` and
`monitoring.googleapis.com` on the project yourself — the scripts do not enable
APIs for you. The account that runs them also needs to create a service account
and set project IAM policy, because `provision.sh` creates the audit logger
identity and grants it `roles/logging.logWriter`.

**Credentials to have ready.** `provision.sh` pushes each one into an encrypted
KVM. None of them is committed, logged, or passed on the command line:

- A **GitHub fine-grained PAT** scoped to exactly one repository, Issues
  read/write. Use a fine-grained token rather than a classic one, so the token
  and the gateway's allowlist agree on how much it can reach.
- A **Slack bot token** (`xoxb-…`) from an app in your workspace, with the
  `chat:write` and `channels:history` scopes. Add the scopes *and then reinstall
  the app* — Slack does not add a scope to a token it has already issued, and
  the symptom is an `M12` failure that looks like a gateway bug. Invite the bot
  to each channel you want to allowlist, and collect the channel **IDs**
  (`C…`), not the names.
- An **OpenRouter API key**, plus the model IDs the gateway may spend it on.
  Free-tier IDs are fine, and are what the tests assume.

## Setup

Copy the environment file and point it at your own org. The defaults in the
repo are this deployment's, and `config/env.sh` falls back to them for anything
`.env` leaves blank — so if you do not edit it, the scripts will happily deploy
somewhere useless:

```bash
cp .env.example .env
```

Set `APIGEE_ORG`, `APIGEE_ENV`, `APIGEE_ENVGROUP` and `APIGEE_HOST`.
`APIGEE_HOST` must be a bare hostname — no `https://`, no path. The MCP server
refuses to start on anything else, so a config file cannot quietly redirect
every call somewhere you did not intend.

Then provision, supplying the backend credentials in the same run:

```bash
GITHUB_PAT='<pat>' GITHUB_ALLOWED_REPO='owner/repo' SLACK_BOT_TOKEN='xoxb-...' SLACK_ALLOWED_CHANNELS='C09ABCDEF' OPENROUTER_API_KEY='<key>' LLM_ALLOWED_MODELS='vendor/model:free' bash scripts/provision.sh
```

```bash
bash scripts/deploy.sh
```

**On a fresh org, provision before you deploy.** `provision.sh` creates the
`apigee-airlock-logger` service account, and `deploy.sh` attaches that identity
to every bundle with `-s`. If you deploy first, you deploy against a service
account that does not exist yet. After that first run the order does not
matter, because both scripts are idempotent. Rerun `provision.sh` whenever
products, apps, KVM values or allowlists change, and `deploy.sh` whenever a
policy changes.

`provision.sh` writes the resulting consumer keys back into `.env` — keys
only, never secrets. The credentials are independent of each other: the script
writes only the KVM entries whose variables are set, and tests for anything you
did not provision skip with a reason instead of failing.

Then wire the alarms and confirm the whole thing:

```bash
bash scripts/monitoring.sh
```

```bash
bash scripts/smoke.sh
```

`monitoring.sh` needs one thing done by hand first: a Slack notification
channel, created in the Monitoring console and described under
[the audit trail](#the-audit-trail). Without it the metrics and policies are
still created — they just have nowhere to ring.

`smoke.sh` is the gate. A green run is your evidence that the gateway really
enforces what this README claims, rather than that the scripts merely reported
success.

### When `smoke.sh` reports a security failure

Check `gcloud` before anything else:

```bash
gcloud auth list && gcloud config get-value project
```

The suite reads the live KVM to decide which tests can run, because what your
local `.env` says is not evidence about the gateway. If your shell is not
authenticated, that read returns `401`. The pre-check treats `401` as *"the
allowlist was never provisioned"*, so a correct `200` on a channel that really
is allowlisted gets reported as a gateway letting an unprovisioned request
through. The alarm is real, but the diagnosis is backwards. The usual cause is
an `(unset)` account here, which is easy to hit by running the suite from a
different shell than the one you provisioned from. The gateway is fine.

### Supplying the GitHub credential

The PAT is never committed, never hardcoded, and never passed as a command-line
argument, because anyone on the machine can read argv out of the process table.
`provision.sh` reads it from the environment and pipes it to the Apigee control
plane on stdin:

```bash
GITHUB_PAT='<your token>' GITHUB_ALLOWED_REPO='owner/repo' bash scripts/provision.sh
```

A fine-grained PAT scoped to that one repository with Issues read/write is
enough. Once it is in the KVM you cannot read the value back out: Apigee returns
it only to policies, and `KVM-Get-GitHub-PAT` writes it into a `private.*`
variable, which Apigee masks even in a debug trace.

`GITHUB_ALLOWED_REPO` goes into a separate, unencrypted `gateway-config` KVM.
The proxy compares the requested `owner/repo` against it and returns 403 for
anything else. It does not echo back which repository was asked for, so the
error cannot be used to probe for private repositories.

That comparison is literal. The proxy pulls two path segments out of the
request and checks them against the stored value, so the exact format you store
matters more than it appears to. Paste a browser URL, which is the obvious thing
to try, and you get a value no request can ever match. Worse, the refusal reads
`not scoped for that operation`, which points at the caller's API key instead of
at the allowlist.

So the format is settled at the moment a human supplies it.
`scripts/normalize_repo.py` reduces a github.com URL to `owner/repo` and rejects
anything that does not resolve to exactly one repository. That includes URLs
pointing deeper than the repository root: `/owner/repo/issues` could mean the
issues of `owner/repo`, or a repository actually named `issues`, and an
allowlist should not guess. A value that cannot be read fails the run. An
allowlist nobody can satisfy is not a safe default; it is a gateway that has
quietly stopped working while still reporting success.

The opposite failure is the dangerous one, and `smoke.sh M5` checks for it in
the only situation where you can observe it: before the KVM has been provisioned
at all. A missing entry leaves `gh.allowed_repo` null, and if a null comparison
came out *equal*, the stored PAT would be handed every repository on GitHub. So
an unprovisioned allowlist has to deny, and the suite confirms that it does
before it skips the tests that need a real repository.

### Supplying the Slack credential

Same rules again, and the same script:

```bash
SLACK_BOT_TOKEN='<xoxb-...>' SLACK_ALLOWED_CHANNELS='C09ABCDEF,C09GHIJKL' bash scripts/provision.sh
```

The token goes into `backend-secrets` as `slack_bot_token`.
`KVM-Get-Slack-Token` reads it into a `private.*` variable and injects it at
target time.

The channels go into `gateway-config`, but as **one entry per channel**,
`slack_channel_<ID>`, rather than one comma-joined list. That is not a style
choice. Apigee conditions cannot test whether a value is in a list, so a single
entry could only be compared with `=`, and every channel after the first would
silently be denied. Instead the proxy builds the key from the requested channel
and asks the KVM whether that entry exists. A channel nobody provisioned leaves
the comparison variable null, and nothing equals null, so the default is to
deny.

Channels are identified by **ID** (`C…`), never by `#name`. Resolving a name
would mean calling `conversations.list`, and a gateway that can list a
workspace's channels has already granted the read the allowlist exists to
withhold. So no tool here can list channels, and both agents are told to ask the
human for an ID rather than guess one. A guess costs the user a turn and
produces a logged attempt against the allowlist, which looks exactly like
enumeration to whoever is reading the alert.

The refusal deliberately tells the caller nothing useful: 403 `not authorized
for that Slack channel`, with the requested ID left out of the body. Slack's own
errors would give that away, since `channel_not_found` versus `not_in_channel`
tells a caller whether a channel it guessed at exists. That is why
`slack_outcome.js` keeps Slack's error string for the audit and never for the
caller.

Two things about the Slack API mean the write path cannot be a simple
pass-through:

- **Slack reports failures with HTTP 200.** An application error arrives as
  `200 {"ok":false,"error":"missing_scope"}`. Left alone, the audit would record
  `outcome: ok` for a call that did nothing, every alert would undercount, and
  the agent would be told its message was posted. `JS-Slack-Outcome` rewrites
  the status from the body before either the caller or the audit sees it.
- **A message body is itself a capability.** Slack would accept `blocks` and
  `attachments` (interactive elements posted into a channel), `username` and
  `icon_emoji` (posting as somebody else), and mention markup — `<!channel>`,
  `<!here>`, `<@U…>` — which pages real people from inside the message *text*,
  with no separate field to strip. So `slack_message.js` rebuilds the request
  from `{channel, text}` alone and defuses the markup in the text itself. It is
  the same argument as `assignees` on a GitHub issue, only louder.

### Supplying the model credential

Same rules, same script:

```bash
OPENROUTER_API_KEY='<your key>' LLM_ALLOWED_MODELS='vendor/model-a,vendor/model-b' LLM_MAX_TOKENS=1024 bash scripts/provision.sh
```

The key goes into `backend-secrets` as `openrouter_api_key`, and `llm-v1`
injects it at target time exactly as it does the PAT. The other two go into the
unencrypted `gateway-config` KVM, because they are policy rather than secrets,
and are meant to be changed without touching a credential.

Those two behave differently when they are missing, on purpose. A missing
`llm_allowed_models` denies **every** model, because an allowlist nobody can
satisfy is the safe direction — the same argument as the repo allowlist above. A
missing `llm_max_tokens` falls back to a built-in ceiling rather than to no
ceiling, because what it guards against is cost, and "unlimited" is not a
cautious reading of a missing number. Deny by default on access; keep a ceiling
on spend.

The first entry in `LLM_ALLOWED_MODELS` is also the default model for
`adk-agents/`, so the list decides both what is allowed and what actually gets
used.

## Registering with an MCP client

You can register both identities at once, but their tool names collide. In
practice, enable one at a time — or keep the reader enabled and switch the
operator on only when you actually need a write.

Any MCP-compatible client — Claude Code, Claude Desktop, or another agent
runtime — needs the same four things. Where its config file lives, and what its
config format is called, does not change the list:

- **A launch command** — how to start `mcp-server/server.py`. With `uv`
  installed, that is `uv run --directory /path/to/apigee-mcp-gateway/mcp-server
  server.py`. Adjust the path separator (`/` vs `\`) for your OS, and use a
  plain `python` invocation if you are not using `uv`.
- **`APIGEE_HOST`** — the bare hostname of your Apigee target, e.g.
  `apigee-airlock-eval.nip.io`.
- **`AGENT_API_KEY`** — the reader or operator key from your `.env`.
- **`AGENT_LABEL`** — `reader` or `operator`, matching the key you supplied.

Check your client's documentation for where MCP server definitions go — for
example, a `mcpServers` block in a JSON config file. Register two entries, one
per identity, each with its own command, args and env block:

```json
{
  "mcpServers": {
    "airlock-reader": {
      "command": "uv",
      "args": [
        "run",
        "--directory",
        "/path/to/apigee-mcp-gateway/mcp-server",
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
        "/path/to/apigee-mcp-gateway/mcp-server",
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

`APIGEE_HOST` must be a bare hostname. The server refuses to start on a value
that contains a scheme or a path, so a config change cannot quietly redirect
every tool call somewhere else.

It also refuses to start if `GITHUB_TOKEN`, `GITHUB_PAT`, `GH_TOKEN`,
`HA_TOKEN`, `HOME_ASSISTANT_TOKEN`, `OPENWEATHER_API_KEY`, `SLACK_BOT_TOKEN`,
`SLACK_USER_TOKEN`, `SLACK_APP_TOKEN` or `SLACK_WEBHOOK_URL` is present in its
environment. If a backend credential is reachable from the agent's process, the
airlock is already open, and crashing is better than working. The webhook URL is
on that list even though it is not a token: anyone holding one can post to a
channel without going through the gateway at all.

Check the result with the `whoami` tool. It reports the gateway and the
identity label, never the key.

## Tests

```bash
bash scripts/smoke.sh
```

The tests are cumulative: every milestone's tests keep running in each later
one. Filter with `scripts/smoke.sh M4`. Tests that need credentials skip with an
explanation instead of failing.

Writes are opt-in, because they have real, visible side effects: an issue on
somebody's repository, and a message every human in a Slack channel sees the
moment it lands.

```bash
AIRLOCK_WRITE_TESTS=1 bash scripts/smoke.sh M5 M12
```

`M12` covers Slack. The test message deliberately carries `<!channel>`, `blocks`
and `username`, and the assertion is on what comes back: the broadcast markup
arrives defused as `@channel`, and the other two fields are gone.

The MCP tests run inside the server's own virtualenv, because the `mcp` client
library is a dependency of the server and not of this repository:

```bash
uv run --directory mcp-server --with pytest --with requests python -m pytest tests/test_mcp_server.py -q
```

## The audit trail

Every request through either proxy writes one JSON record to Cloud Logging, at
`projects/<org>/logs/agent-airlock-audit`. Refusals are recorded exactly like
successes. The question the log exists to answer is "what did the compromised
agent *try* to do", and a log of only the calls that worked cannot answer it.

```json
{"ts":"2026-08-23T01:27:14.398Z","agent":"agent-reader","client_key_fp":"4ddfa347",
 "proxy":"github-v1","revision":"18","verb":"POST",
 "path":"/repos/your-org/your-repo/issues","action":"github.issues.create",
 "status":403,"outcome":"denied",
 "fault":"InvalidApiKeyForGivenResource","latency_ms":47,
 "client_ip":"203.0.113.9","forwarded_for":"203.0.113.9, 198.51.100.5"}
```

The caller's API key is **fingerprinted, never logged**. Apigee exposes the key
as `client_id`, and logging that verbatim would make read access to the audit as
good as holding the key. So the record carries eight hex digits of an FNV-1a
hash instead. That is enough to group one caller's records, and to match a key
you already hold against the log. It is not enough to rebuild the key.

The caller's address is recorded as a claim, not a fact, because that is what it
is. The gateway sits behind an external ALB, so the only place the caller's IP
appears is `X-Forwarded-For`. The ALB *appends* to that header rather than
replacing it, so the first element is the one hop a caller can write themselves.
`client_ip` is that first element. `forwarded_for` keeps the whole chain, so the
hops Google actually added are there to check the claim against.

Reading that header is the one part of the audit that cannot be done where the
rest of the record is assembled. The builder runs in the response flow for a
served request, and by then `X-Forwarded-For` describes *Apigee's* call to the
backend, not the client's call to Apigee. Reading it there named a Google front
end as the caller on every request that succeeded, while refusals, built during
the request phase, were correct. A field that is right only on the requests
nobody investigates is worse than no field at all. `AM-Capture-Caller` takes a
snapshot of the header at the top of `sf-inbound-security`, ahead of the key
check so that an unauthenticated request is attributed too, and the builder
reads that snapshot.

Attribution has its own version of the same problem, and the sample record above
is what it looks like once fixed. That refusal is an API Product scope refusal:
a real, registered key used for a resource it was not granted. Apigee raises it
from inside `VerifyAPIKey`, before the policy has published anything. A debug
session over the whole transaction shows `developer.app.name`,
`verifyapikey.VA-VerifyAPIKey.app.name` and every other identity variable unset,
and the app's name nowhere in the flow at all. So the record read
`"agent":"unauthenticated"` for a caller the gateway had recognised perfectly
well and simply refused — the opposite of what happened, on exactly the record
an investigation reaches for first.

`AE-Resolve-App` looks the app up from the consumer key directly. That lookup
does not depend on `VerifyAPIKey`, so it survives its failure. It runs only when
nothing else has produced a name, so a served request never pays for it. And it
resolves the *credential*, not the authorization: the name says "this request
carried the key registered to that app", while `outcome` alongside it still says
`denied`. A key registered to nothing resolves to nothing, and that caller is
correctly still `unauthenticated`.

That lookup came with a cost, and it is the kind that usually goes unnoticed.
`AccessEntity` does not return a single field. It returns the whole app entity,
and the whole app entity includes every consumer secret the app holds, in
plaintext, in a flow variable. Apigee masks `client_id` and `access_token` in
traces by default and knows nothing about that variable. So until
`scripts/provision.sh` added `AccessEntity.AE-Resolve-App` to the environment's
debug mask, anyone able to start a debug session could read the credentials this
gateway exists to keep out of reach. `EV-App-Name` lifts the one attribute it
needs and the rest is never logged, but the mask is what stops it being readable
anyway. The mask lives on the environment rather than in a bundle, because what
may be observed here is a property of the environment, and because it has to be
in force before the proxy that needs it is deployed.

Nothing taken from a response body is ever logged, and the record is built
*after* the redaction pass, so it cannot describe a body the caller was not
allowed to see.

`scripts/monitoring.sh` builds the log-based metric `airlock_github_writes`
(issue-creation attempts, per agent, per outcome — refusals included) and an
alert policy that fires above 20 per agent per hour.

A third metric, `airlock_denied_actions`, counts every call the gateway did
*not* serve, labelled with the agent, the action, the verdict and the name of
the policy that refused. Its alert policy answers the question "did an agent do
something it is not allowed to do?", and its threshold is zero. A single 403
means an agent reached for a repository, a Slack channel or a model outside its
allowlist, and there is no number of those per hour that counts as normal.

A second condition on the same policy watches for a *burst* of 401s and other
4xx from one identity. Ordinary client breakage produces a steady trickle and
deliberately does not fire; credential guessing and retry storms produce a
spike. Throttling is counted by the metric but alarmed on by neither condition:
a throttled agent is one the quota is already handling, and the quota has its
own alarm.

Running `scripts/smoke.sh` fires the refusal alarm, because M4, M5 and M12
provoke real 403s and the threshold is zero. That is correct behaviour, and on a
first run it is worth watching it arrive in Slack. To run the suite quietly, set
`AIRLOCK_SNOOZE_ALERTS=1`. It snoozes that one policy for the length of the run
(`AIRLOCK_SNOOZE_MINUTES`, default 30), and the snooze expires on its own, so an
interrupted run cannot leave the alarm switched off.

All three alarms — the write burst, the model spend and the refusal — go to
every channel named in `ALERT_CHANNEL_TITLES`, which defaults to the single
Slack channel `ai-gateway-alerts`. Slack is where these get *seen*, since a
burst of denied writes is something somebody should look at within minutes. It
is also the only delivery path by default, and that has a real cost worth
naming: a workspace can be left, archived or rate-limited, and one path is one
point of silence. Add an email channel to the list if that matters more to you
than the extra noise.

The value is matched **literally against the channel's Monitoring display
name**, which is not the same string as the Slack channel it posts to. The two
match here only because the console copies one from the other. Rename either
side and the alarms are no longer wired up.

**Create the channel before running the script.** `monitoring.sh` looks channels
up and never creates one. Not because it cannot, but because the only token it
could create one with is the same bot token the gateway injects from the KVM,
and copying a credential into a second system widens the damage a leak does and
adds another place a rotation has to reach.

In the Monitoring console: Alerting → Edit notification channels → Slack →
*Add new*. That runs Google's own OAuth flow, mints a token belonging to
Google's Slack app, and invites its bot to the channel. Name it to match
`ALERT_CHANNEL_TITLES` and rerun the script. A name the script cannot resolve is
printed and skipped rather than silently dropped, because an alert policy that
quietly ends up with no channels still shows as healthy.

Point it at an alert channel the gateway is *not* allowlisted for. Alerting
about an agent through a channel that same agent can write to is a loop worth
not building.

Note that this path is Google's own bot posting to Slack, not the gateway's. The
alerting stack does not go through `slack-v1`, and that is deliberate: an alarm
that depends on the thing it is watching is not an alarm.

Replay a session with:

```bash
uv run --directory mcp-server --with requests python ../tests/audit_replay.py
```

To prove the alert actually fires, drive the threshold with *denied* writes.
That is also the case worth alerting on, since a prompt-injected agent that
keeps retrying against policy looks exactly like this. Nothing is created on any
repository, and the PAT is not needed:

```bash
for i in $(seq 1 25); do curl -s -o /dev/null -X POST -H "x-api-key: $AGENT_READER_KEY" -H 'Content-Type: application/json' -d '{"title":"alert drill"}' "$APIGEE_BASE/github/v1/repos/octocat/Hello-World/issues"; sleep 0.5; done
```

The `sleep` keeps the loop under the 10-per-second SpikeArrest, which would
otherwise turn the attempts into throttles and count them under a different
outcome. The metric adds up over one hour, so the incident lands a few minutes
later and closes itself after 30.

## Analytics views

`scripts/reports.sh` creates three custom reports. Rerunning it updates them
rather than piling up duplicates:

| View | Answers |
| --- | --- |
| requests per agent | is one identity suddenly doing far more than it used to |
| error rate per proxy | errors against total traffic, so the ratio is readable |
| latency per target | avg and max upstream time, plus total, per backend |

The gap between `total_response_time` and `target_response_time` is what the
airlock itself costs: every policy in the chain, the key check, the KVM read,
the redaction pass. On this deployment that is around **90–100ms** per
request.

**p95 is not one of them. That is a platform limit, not a choice.** Apigee's
stats API supports `sum`, `avg`, `min` and `max`; `p95(...)` and
`percentile95(...)` are both rejected as unsupported functions. Worse, the
custom-report API does not check metric names at all. A report selecting
`p95_total_response_time` is created successfully and then renders nothing, so
"the report was created" proves only that a POST succeeded. The percentile is
therefore computed from the audit log, which has the per-request numbers to do
it honestly:

```bash
python tests/latency_p95.py --hours 24
```

`smoke.sh M7` checks both halves of this: that each view's metric-and-dimension
pair really does return rows from the stats API, and that `p95(...)` is *still*
rejected. If Apigee ever grows a percentile function, that test fails and the
workaround can be deleted.

### Why the audit is split across two shared flows

`sf-audit-build` assembles the record; `sf-audit-log` writes it. They are
separate because **Apigee's `PostClientFlow` runs `MessageLogging` policies and
nothing else.** A `JavaScript` step placed there is reported in a debug trace as
having run successfully — `result: true`, execution time zero — while setting no
variables at all. The record came out empty and Cloud Logging discarded the
write, with every policy claiming success.

So the build runs where JavaScript actually executes: `PostFlow/Response` for a
served request, and both fault rules for a refused one, since a refusal
short-circuits straight past `PostFlow`. Only the write stays in
`PostClientFlow`, which is the one hook that always runs after the response has
reached the client. `tests/check_audit_wiring.py` asserts that shape so it
cannot quietly regress.

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
- the served and refused paths agree on who the caller was. The two records are
  built at different points in the flow, and comparing them is the only way to
  catch one of them silently recording the load balancer instead
- a call refused at the product scope still says which agent was refused. The
  fault means the key *was* recognised, so a record calling that caller
  unauthenticated would be hiding something the gateway knows
- the app lookup's output variable is in the environment's debug mask. It
  carries the app's consumer secrets, and a trace is a surface like any other
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

Each row names the mechanism and the test that would fail if it stopped
working. Nothing here is claimed on inspection alone.

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

The row the design really rests on is the first one. Everything else limits
what a compromised agent can do. That row is why compromising the agent does not
hand anyone a GitHub token in the first place.

