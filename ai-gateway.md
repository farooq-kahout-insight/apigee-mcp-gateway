# ai-gateway.md — Apigee as a secure AI gateway for agentic workflows

Implementation guide for the next phase of this repo. Written for an
implementing agent that has this repository checked out but no memory of how it
was built. Read `ARCHITECTURE.md` first for the current state; this document
only describes the delta.

## What exists today (do not rebuild it)

- Apigee eval org `your-gcp-project-id`, env `eval`, reachable at
  `https://YOUR_LB_IP.nip.io` (values live in `config/env.sh` / `.env`).
- Two proxies: `weather-v1`, `github-v1`. Six shared flows:
  `sf-inbound-security`, `sf-target-hygiene`, `sf-outbound-redaction`,
  `sf-fault-sanitizer`, `sf-audit-build`, `sf-audit-log`.
- Two agent identities (Apigee developer apps): `agent-reader` → product
  `tools-readonly`, `agent-operator` → product `tools-operator`. One consumer
  key each, in the gitignored `.env`.
- Encrypted KVM `backend-secrets` (holds `github_pat`), plain KVM
  `gateway-config` (holds `github_allowed_repo`). Lookups fail closed.
- An MCP server (`mcp-server/server.py`) whose only route to any backend is the
  gateway; it fail-fasts if a backend credential is present in its environment.
- Audit: every request writes one JSON record to Cloud Logging
  (`agent-airlock-audit`), refusals included; log-based metric + email alert.
- `scripts/deploy.sh` auto-discovers every directory under `proxies/` and
  `sharedflows/` — a new proxy needs no deploy-script change. `scripts/provision.sh`
  idempotently creates products/developer/apps from `config/products/*.json`
  and `config/apps.json`.
- Gate: `bash scripts/smoke.sh` — cumulative, currently 67 passed / 0 failed /
  0 skipped. **It must never go red.** Commit style: `M<n>: <summary>`.
  M8 (OAuth client credentials) was cancelled by the user; new work starts at
  **M9**. Do not renumber.

## What is being added

Two Google ADK agents (`airlock-reader`, `airlock-operator`) that obtain their
**LLM** through the gateway, not just their tools. Apigee exposes an
OpenAI-compatible endpoint, backed by OpenRouter; the OpenRouter API key lives
in the encrypted KVM and is injected server-side. The agents hold only their
existing Apigee consumer keys — the same identity now covers both planes:

```
            ┌────────────────────────  data/tool plane  ───────────────────────┐
ADK agent ──┤ MCP server (stdio) ──► /weather/v1, /github/v1 ──► backends      │
 (reader /  └──────────────────────────────────────────────────────────────────┘
  operator) ┌────────────────────────  model plane  ──────────────────────────┐
            │ OpenAI-compatible client ──► /llm/v1 ──► openrouter.ai          │
            └──────────────────────────────────────────────────────────────────┘
                     both hops authenticated by the SAME consumer key,
                     both hops audited into the SAME Cloud Logging stream
```

That symmetry is the demo's thesis: one revocable identity, one quota budget,
one audit trail, whether the agent is calling a tool or thinking.

---

## M9 — `llm-v1` proxy: OpenAI-compatible endpoint with KVM credential injection

### Proxy shape

New proxy `proxies/llm-v1/`, base path `/llm/v1`, modeled directly on
`github-v1` (copy its bundle layout). Target:

```xml
<HTTPTargetConnection><URL>https://openrouter.ai/api/v1</URL></HTTPTargetConnection>
```

Apigee appends `proxy.pathsuffix`, so `/llm/v1/chat/completions` →
`https://openrouter.ai/api/v1/chat/completions`. Expose exactly two flows and
reject the rest with the existing RF-Unknown-Resource pattern:

- `POST /chat/completions`
- `GET  /models` (harmless discovery; lets OpenAI SDKs probe)

### Authentication adapter (the one new inbound wrinkle)

OpenAI SDKs send credentials as `Authorization: Bearer <key>`, but
`VA-VerifyAPIKey` reads `request.header.x-api-key`. Do **not** modify the
shared flow. Instead, first policy in the llm-v1 proxy PreFlow, before
`FC-Inbound-Security`:

- `EV-Bearer-Key`: ExtractVariables with pattern `Bearer {llm.bearer_key}`
  against `request.header.Authorization`.
- `AM-Bearer-To-ApiKey`: if `x-api-key` is absent and `llm.bearer_key` is set,
  set header `x-api-key = {llm.bearer_key}`.

`sf-target-hygiene` already strips both `Authorization` and `x-api-key` before
the target, so the consumer key can never leak to OpenRouter. Keep the target
PreFlow order **exactly** as github-v1's (order is load-bearing):
`FC-Target-Hygiene` → `KVM-Get-OpenRouter-Key` → `AM-Inject-OpenRouter-Auth`.

### Credential injection

- `KVM-Get-OpenRouter-Key`: clone of `KVM-Get-GitHub-PAT`; map
  `backend-secrets`, key `openrouter_api_key`, assign to
  `private.openrouter_key` (the `private.` prefix keeps it masked in trace).
- `AM-Inject-OpenRouter-Auth`: clone of `AM-Inject-GitHub-Auth`;
  `Authorization: Bearer {private.openrouter_key}`, plus
  `User-Agent: agent-airlock-gateway`. Keep
  `IgnoreUnresolvedVariables=false` — an empty KVM lookup must fail into a
  sanitized 500, never send a literal `{private.openrouter_key}` upstream.

### Inbound screening: the body-pattern conflict, and its resolution

`sf-inbound-security` runs `REP-Injection`, which matches SQL/XSS patterns
against **`request.content`**. A chat prompt is arbitrary natural language —
"explain what UNION SELECT does" must not 400. But the query-string patterns
must keep running, and the existing proxies' body screening must not change
(smoke has explicit M4 tests for body patterns).

Resolution — split, don't fork:

1. In `sf-inbound-security`, split `REP-Injection` into `REP-Injection-Query`
   (the `request.querystring` patterns) and `REP-Injection-Body` (the
   `request.content` patterns). Same patterns, verbatim.
2. Step both in the shared flow where the single policy is today. Give the body
   step a condition: `(inbound.skip_body_screen != "true")`.
3. llm-v1 sets `inbound.skip_body_screen = "true"` (AssignMessage) before
   `FC-Inbound-Security`. weather-v1 and github-v1 set nothing and keep
   today's behavior exactly.

Similarly for JSON threat protection: the shared `JTP-JSONThreatProtection`
caps `StringValueLength` at 8192, too small for real prompts. Give that step
the condition `(inbound.jtp != "custom")`; llm-v1 sets `inbound.jtp = "custom"`
and carries its own `JTP-LLM` (ContainerDepth 10, ObjectEntryCount 200,
ArrayElementCount 1000 — messages arrays are long — StringValueLength 65536).
The body is still bounded, just with LLM-shaped limits.

Run the full smoke suite after this refactor **before** building anything else;
this is the only change that touches existing proxies' behavior surface.

### LLM guardrails (`JS-LLM-Guard`)

One JavaScript policy on the proxy request flow (source file under `shared/js/`
— `deploy.sh` copies that directory into every bundle; follow the
`JS-Build-Issue` precedent and give it a Node-runnable unit-test file
`tests/test_llm_guard.js`). It parses the JSON body once and enforces:

- **Model allowlist, fail closed.** `KVM-Get-LLM-Config` (map
  `gateway-config`, keys `llm_allowed_models`, `llm_max_tokens`) runs before
  it. If `llm_allowed_models` is unset → 403 for everything (mirror the
  github repo-allowlist stance). If `body.model` is not in the
  comma-separated list → 403 via `RF-Model-Denied`, generic message, and do
  not echo the allowlist or the requested model back.
- **Token ceiling.** Clamp `max_tokens` to `llm_max_tokens` (default 1024 if
  the KVM entry is absent — clamping may fail open to a default, unlike the
  allowlist, because the blast radius is cost, not access). Insert it when the
  caller omitted it entirely.
- **Streaming off in v1.** If `stream: true` → 400 `RF-Stream-Unsupported`.
  Reason, and record it in a comment: Apigee cannot run response policies over
  an SSE stream, so streaming would silently disable outbound redaction,
  usage extraction, and the audit's status/latency fields. Revisit only as its
  own milestone with that tradeoff stated.
- **Strip routing overrides.** Delete OpenRouter-specific fields that would
  let a caller re-route or re-price the request: `provider`, `transforms`,
  `models` (the fallback-array form), `route`. The gateway decides routing
  policy, not the caller.
- Re-serialize the body. Never log `messages` content.

### Rate limiting and a separate LLM budget

`FC-Inbound-Security` already gives llm-v1 SpikeArrest (10ps per `client_id`)
and the product quota. But the product quota is one bucket per identity across
all proxies, and model calls deserve their own, tighter budget. Add
`Q-LLM-Quota` in the llm-v1 proxy after the shared flow:

- `Identifier`: `client_id` (Apigee scopes the counter per policy, so this is
  already a separate bucket from `Q-Quota`).
- `Allow countRef="verifyapikey.VA-VerifyAPIKey.apiproduct.llm_quota"`,
  fallback `50`; interval 1 hour. Set the `llm_quota` custom attribute on both
  products in provisioning (reader lower than operator, e.g. 30 vs 100), so
  the budget stays product-managed like everything else.

### Response path

- `sf-outbound-redaction` runs as-is: completions are JSON, and the email/PII
  redaction must preserve the OpenAI response shape (`choices[].message.content`
  is a string — the existing JS redactor already operates on JSON string
  values; add a unit test that a redacted completion still parses as a valid
  chat response).
- `EV-LLM-Usage` (response flow): extract `$.usage.prompt_tokens`,
  `$.usage.completion_tokens`, `$.usage.total_tokens`, `$.model` into flow
  variables `llm.usage.*` / `llm.model`.
- Fault mapping in `sf-fault-sanitizer` terms: an upstream **401/403 from
  OpenRouter** means the *gateway's* key is bad — surface a sanitized 502
  with the generic `{"error","message"}` shape, never anything naming
  OpenRouter or the key. An upstream **429** passes through as 429 with the
  sanitized body so callers keep the retry signal. Everything else follows
  the existing uniform error contract.

### Provisioning and config deltas

- `config/products/tools-readonly.json` and `tools-operator.json`: add an
  `apiSource: "llm-v1"` block with `POST /chat/completions` and
  `GET /models`. Same two identities, same keys — **no new apps**.
- `scripts/provision.sh`: read `OPENROUTER_API_KEY` from the environment and
  pipe it to the `backend-secrets` KVM on stdin, exactly like `GITHUB_PAT`
  (never argv, never echoed, never committed). Also upsert `gateway-config`
  entries `llm_allowed_models` and `llm_max_tokens` from env vars
  `LLM_ALLOWED_MODELS` / `LLM_MAX_TOKENS`.
- `.env.example`: add `OPENROUTER_API_KEY=` (provision-time only, with the
  same warning comment as the PAT), `LLM_ALLOWED_MODELS=`, `LLM_MAX_TOKENS=`.
- **Ask the human** for the OpenRouter key at provision time; never generate,
  guess, or print one. Suggest the allowlist hold one or two cheap/free
  models (e.g. a `:free`-suffixed model on OpenRouter) — this is a demo, and
  the allowlist existing is the point, not the model quality.

### M9 smoke tests (append to `scripts/smoke.sh`, cumulative)

1. `POST /llm/v1/chat/completions` with no key → 401.
2. Same with `Authorization: Bearer $AGENT_READER_KEY` and an allowlisted
   model → 200 with `choices[0].message.content` non-empty (proves the
   bearer→x-api-key adapter AND KVM injection end-to-end).
3. Same with `x-api-key` header instead of bearer → 200 (both spellings work).
4. Non-allowlisted model (`openai/gpt-4o`) → 403; response does not echo the
   model name or the allowlist.
5. `"stream": true` → 400.
6. Prompt containing `UNION SELECT` in a message body → **200** (body screen
   bypassed for llm-v1 only).
7. The same string in the *query string* of an llm-v1 URL → 400 (query screen
   still armed).
8. Existing M4 body-injection tests against weather/github still pass
   (the split changed nothing for them).
9. Response contains no `sk-or-` prefix and no `openrouter` string
   (credential and upstream identity don't leak).
10. `max_tokens: 999999` in request → completion's `usage.completion_tokens`
    ≤ the KVM cap (clamp works).
11. Reader identity exhausting `llm_quota` → 429 while a weather GET with the
    same key still succeeds (separate buckets proven).

---

## M10 — LLM observability: usage in the audit, spend alerting

- Extend the audit record builder (`shared/js` audit source + its unit tests in
  `tests/test_audit.js`) with optional fields, present only when set:
  `model`, `tokens_prompt`, `tokens_completion`, `tokens_total`. **Never**
  `messages`, never completion text — the audit answers "who spent what,
  where", not "what was said". Action name: `llm.chat`.
- Log-based metric `airlock_llm_tokens`: value extracted from
  `jsonPayload.tokens_total`, labeled by `agent`. Alert policy on the existing
  `Email Alert` channel: fire when hourly token sum exceeds a threshold
  (pick something the demo can actually trip, mirroring the
  `airlock_github_writes` > 20/hour precedent).
- `tests/audit_replay.py` gains the llm fields; a replayed session should now
  show tool calls and model calls interleaved under the same `agent` and
  `client_key_fp`.
- Smoke: audit entry for an llm call carries `tokens_total > 0` and no message
  content; a denied model request is audited as `denied` with the agent named.

---

## M11 — the ADK agents

New top-level directory `adk-agents/` (Python, `uv`-managed like
`mcp-server/`, own `pyproject.toml`, `google-adk` + `litellm` deps).

### Two agents, one code path

`adk-agents/airlock_reader/` and `adk-agents/airlock_operator/` — thin
configs over one shared factory module. Per ADK convention each package
exposes `root_agent` in `agent.py` so `adk run adk-agents/airlock_reader` and
`adk web` both work.

- **Model plane:** `LiteLlm(model="openai/<allowlisted-model>",
  api_base="https://" + APIGEE_HOST + "/llm/v1",
  api_key=AGENT_API_KEY)`. The `openai/` LiteLLM prefix selects the
  OpenAI-compatible driver; the key is the agent's *consumer key*, which the
  gateway swaps for the real OpenRouter credential.
- **Tool plane:** ADK `MCPToolset` over stdio, launching the existing
  `mcp-server/server.py` via `uv run --directory ../mcp-server server.py`
  with `APIGEE_HOST`, `AGENT_API_KEY`, `AGENT_LABEL` in its env — the same
  registration contract `README.md` documents for Claude Code. Reader passes
  the reader key; operator the operator key. Permissions therefore come from
  the API products, not from agent code: the reader agent physically cannot
  create an issue even if prompted to, and the refusal shows up in the audit.
- **Environment contract (mirror `mcp-server/server.py` exactly):** require
  `APIGEE_HOST` (bare hostname — refuse a scheme or path), `AGENT_API_KEY`,
  `AGENT_LABEL`; **fail fast at startup** if `OPENROUTER_API_KEY`,
  `OPENAI_API_KEY`, `GITHUB_TOKEN`, `GITHUB_PAT`, `GH_TOKEN` or any other
  backend credential is present in the process environment. If the agent's
  process can reach a real credential, the airlock is already open; crashing
  is better than working.
- Give each agent a short system instruction that names its identity and
  scope ("you are airlock-reader; you can look things up but not change
  them") so the demo's refusals read as the gateway enforcing what the prompt
  already admitted.

### M11 tests

- Unit: factory refuses schemed `APIGEE_HOST`; refuses when a backend
  credential is in env; reader/operator wire the right key and label.
- Integration (smoke, guarded like the MCP tests): a scripted single-turn run
  of the reader agent answering a weather question — asserts the answer is
  non-empty and that a new audit record with `action: "llm.chat"` and
  `agent: "agent-reader"` appeared. Skip with explanation when ADK is not
  installed, per the suite's existing skip discipline.
- The write-path demo (operator files an issue *decided by the LLM*) stays
  behind `AIRLOCK_WRITE_TESTS=1`.

---

## M12 — docs and demo integration

- `ARCHITECTURE.md`: add the model plane to the traffic-flow diagram and a
  threat-model row per new control (key custody for OpenRouter, model
  allowlist, token ceiling, spend alert, prompt privacy in audit).
- `DEMO.md`: an Act 9 — talk to the reader agent via `adk web`, watch a
  weather answer arrive; ask it to open an issue and watch the refusal; ask
  the operator and watch it succeed; then `audit_replay.py` showing the whole
  conversation — tool calls and model calls — as one identity's session.
- `README.md`: setup additions (OpenRouter key provisioning, ADK agent
  registration/run commands).

---

## Ground rules carried over (binding)

- Never print, commit, or pass as argv: the OpenRouter key, the GitHub PAT,
  consumer secrets. Consumer *keys* may live in local `.env` / `.mcp.json`
  only (both gitignored).
- Ask the human before: supplying any credential, creating billable GCP
  resources, or the first write to a real external system.
- `bash scripts/smoke.sh` green (currently 67 baseline) before every commit;
  new tests append, old tests never regress. Commits `M9:`…`M12:`.
- Weather + GitHub + LLM only. Home Assistant stays out. M8/OAuth stays
  cancelled — the bearer token accepted at `/llm/v1` is the Apigee consumer
  key, not an OAuth token; do not build a token endpoint.
