# The ADK agents

Two Google ADK agents that reach the outside world only through the gateway —
both the tools they call *and* the model that decides to call them.

Up to here the gateway has stood between an agent and its tools. That leaves the
larger credential untouched: the model key is normally handed to the agent
process, which means the process holds something that can spend money, and the
audit log has a hole in it exactly where the reasoning happened. These agents
close that. There is no provider credential anywhere in the process.

| Plane | How it leaves the process | What it authenticates with |
| --- | --- | --- |
| Model | LiteLLM's OpenAI driver → `https://$APIGEE_HOST/llm/v1` | the agent's Apigee consumer key |
| Tool | ADK `MCPToolset` → stdio → `../mcp-server` → the gateway | the same consumer key |

One key, one identity, two planes. That is what makes a session legible in the
audit: `llm.chat` records and `weather.forecast` records land under the same
`agent` and the same `client_key_fp`, so "what did agent-reader do at 14:03"
has an answer that includes the thinking and not just the doing.

The real OpenRouter key lives in an encrypted Apigee KVM and is injected by
`llm-v1` at target time. The real GitHub PAT lives in the same KVM and is
injected by `github-v1`. Neither has ever been in this directory.

## Two agents, one code path

`airlock_reader/agent.py` and `airlock_operator/agent.py` are ten lines each.
Everything is in `airlock_common/factory.py`, and the two differ only in which
consumer key they present.

That is the point worth being pedantic about: **nothing in this code makes the
reader read-only.** Its instruction says so, and an instruction is a suggestion.
What actually stops it is that `AGENT_READER_KEY` belongs to the
`tools-readonly` API product, and `github-v1` refuses `github.issue.create` for
that product. Prompt the reader into filing an issue and you get a 403 and an
audit record naming `agent-reader` — which is the demo, not a bug.

## Install

```bash
uv sync --directory adk-agents
```

`google-adk`, `litellm`, and `mcp` — the *client* half of the protocol, which
ADK needs to talk to a tool server and does not declare for itself. It is pinned
below 2.0, because 2.x moved the modules ADK imports.

The MCP *server* is not a dependency here. It is launched as a subprocess out of
`../mcp-server` with its own lockfile, which is what keeps its credentials and
its dependency set separate from the agent's.

A missing or wrong-version `mcp` is worth recognising on sight: it surfaces as
`No module named 'mcp'` (or `'mcp.shared.session'`) raised from inside ADK when
an agent module is first imported, which reads like the whole agent stack is
absent — so the smoke suite skips instead of failing, and the real cause is one
line in `pyproject.toml`.

## Environment

Everything comes from the repo `.env` (see `.env.example`). Nothing is read from
a config file inside this directory.

| Variable | Required | Meaning |
| --- | --- | --- |
| `APIGEE_HOST` | yes | Bare hostname of the gateway, e.g. `YOUR_LB_IP.nip.io` |
| `AGENT_READER_KEY` | reader | The reader's consumer key |
| `AGENT_OPERATOR_KEY` | operator | The operator's consumer key |
| `AGENT_API_KEY` | fallback | Used if the identity-specific name is unset |
| `LLM_ALLOWED_MODELS` | yes\* | The gateway's allowlist; the first entry is the default model |
| `AIRLOCK_AGENT_MODEL` | no | Overrides that default with one specific model |

\* one of `LLM_ALLOWED_MODELS` or `AIRLOCK_AGENT_MODEL` must be set. Asking for
a model the gateway does not allowlist gets a 403, not an answer.

`AGENT_API_KEY` exists because the two deployment shapes want different
spellings. `adk run adk-agents/airlock_reader` is one agent in one process and
the generic name reads naturally; `adk web` serves both agents from a single
process, where one generic name cannot mean two different keys. The specific
name wins when both are set, so the second case cannot silently give both agents
whichever key was exported last.

### What it refuses to start with

A scheme or a path in `APIGEE_HOST` is refused. Accepting one would let
configuration redirect every model call and every tool call somewhere else —
the attack this whole architecture exists to prevent, arriving through a config
file instead of through a prompt.

Any of these in the environment is also fatal:

```
OPENROUTER_API_KEY  OPENAI_API_KEY  OPENAI_API_BASE  ANTHROPIC_API_KEY
GITHUB_TOKEN  GITHUB_PAT  GH_TOKEN  HA_TOKEN  HOME_ASSISTANT_TOKEN
OPENWEATHER_API_KEY
```

The same contract `mcp-server/server.py` enforces, plus the model-plane names.
`OPENAI_API_KEY` is the sharpest of them: **LiteLLM reads it from the
environment by itself**, so a key left in a shell would be picked up silently
and every model call would leave through the front door — no allowlist, no token
ceiling, no quota, no audit record, and nothing on the surface to show it. The
process refuses to start rather than work that way.

The filter is applied twice: once at import, and again on the environment handed
to the MCP subprocess. The subprocess does its own check and would refuse too,
but a child that dies at spawn time reaches the model as "the tools are broken",
which is a worse way to learn this.

### The leak the filter cannot see

Importing `airlock_common` sets `LITELLM_MODE=PRODUCTION`, and that line is load-
bearing. LiteLLM's `__init__` runs `dotenv.load_dotenv()` unless `LITELLM_MODE`
holds something other than `DEV`, and `load_dotenv` walks up from site-packages
until it finds a `.env` — which, for an agent run out of this repository, is the
`.env` at the root: the one `provision.sh` reads to fill the KVM, holding
`OPENROUTER_API_KEY` and the GitHub PAT.

So `import litellm` puts both into the process by itself, whatever the launcher
unset. This is worse than the case the startup check was written for. There,
somebody had exported a credential and the check caught them. Here a library
reaches out and fetches one *after* the launcher went to the trouble of
stripping it, and if that import lands after `settings()` has run, the agent
holds a provider key, every check has passed, and nothing anywhere says so.

The value in the environment is deliberately overwritten rather than respected:
`LITELLM_MODE=DEV` re-enables exactly this, and it is the sort of variable
somebody exports once to debug something and never unsets. Two tests in
`tests/test_adk_agents.py` assert the suppression, one of them by setting `DEV`
and reloading the module to check it does not survive.

This is also why `tests/run_agent_turn.py` imports `airlock_common` *before* it
probes for ADK and LiteLLM. Probing first would load the `.env` and then refuse
to start on the credentials it had just loaded — and the refusal would name the
launcher rather than the cause.

## Run one

```bash
adk run adk-agents/airlock_reader
```

```bash
adk web adk-agents
```

Ask the reader for the weather somewhere, then ask it to file a GitHub issue.
The first works. The second comes back as a refusal the agent explains in plain
language, because the instruction tells it to report a 403 rather than look for
another route — there is no other route, and looking for one is the behaviour
the gateway is watching for.

Then look at what the gateway saw:

```bash
bash scripts/reports.sh
```

## Run one turn, non-interactively

`tests/run_agent_turn.py` drives a single turn and prints the answer. It is what
the smoke suite uses:

```bash
python tests/run_agent_turn.py airlock_reader "What is the weather in Lahore?"
```

Its exit codes are the interesting part, because a red test run in this repo is
supposed to mean the gateway did something wrong and nothing else:

| Code | Meaning |
| --- | --- |
| 0 | The agent answered; the answer is on stdout |
| 3 | ADK or LiteLLM is not installed — skip, do not fail |
| 4 | The free model tier rate-limited or ran out of capacity — skip loudly |
| 5 | The agent would not start: a startup contract violation — fail |
| 1 | Anything else — fail |

Code 4 is not politeness. The allowlisted models are free-tier ones and they
return 429 under load; a suite that turned that into a failure would train
everyone to ignore it.

## Tests

```bash
python -m pytest tests/test_adk_agents.py -q
```

These import `airlock_common.factory` and nothing else — no ADK, no LiteLLM —
so the refusals above are testable on a machine that could not run an agent at
all. The properties most worth asserting here are the things this code declines
to do, and a test that only runs where the full stack is installed is a test
that will be skipped on the machine where it matters.

The live end of it is in the suite:

```bash
bash scripts/smoke.sh M11
```
