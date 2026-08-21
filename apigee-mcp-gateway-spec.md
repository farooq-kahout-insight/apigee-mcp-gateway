# Project Spec: Apigee "Airlock" Gateway for MCP Agent Tools

**Codename:** `agent-airlock`
**Goal:** An AI agent (Claude Code via MCP) whose tools never touch backend APIs directly. Every tool call flows through Apigee proxies that enforce identity, scopes, rate limits, payload security, and full audit logging.
**Audience of this document:** A coding agent (e.g., Claude Code) executing the build. Each milestone has explicit tasks and acceptance tests. Do not proceed to the next milestone until the current milestone's tests pass.

---

## 1. Architecture Overview

```
┌─────────────────┐        stdio (MCP)        ┌──────────────────────┐
│  Claude Code /   │◄─────────────────────────►│  MCP Server           │
│  Claude Desktop  │                           │  (Python, FastMCP)    │
│  (MCP client)    │                           │  tools:               │
└─────────────────┘                           │   - get_weather       │
                                              │   - ha_get_states     │
                                              │   - ha_call_service   │
                                              │   - gh_list_issues    │
                                              └──────────┬───────────┘
                                                         │ HTTPS + API key / OAuth
                                                         │ (ONLY credentials the
                                                         │  MCP server holds)
                                                         ▼
                                   ┌─────────────────────────────────────────┐
                                   │  APIGEE X (eval org, env: dev)          │
                                   │                                         │
                                   │  Proxy: weather-v1     Proxy: ha-v1     │
                                   │  Proxy: github-v1                       │
                                   │                                         │
                                   │  Shared policies (per proxy):           │
                                   │   1. VerifyAPIKey / VerifyJWT           │
                                   │   2. Check API Product scope            │
                                   │   3. SpikeArrest (loop protection)      │
                                   │   4. Quota (per-agent budget)           │
                                   │   5. JSONThreatProtection               │
                                   │   6. Path/verb allowlist (RaiseFault)   │
                                   │   7. AssignMessage: inject backend cred │
                                   │   8. Response redaction (JS policy)     │
                                   │   9. MessageLogging → Cloud Logging     │
                                   └────────┬──────────┬──────────┬─────────┘
                                            │          │          │
                                            ▼          ▼          ▼
                                     Open-Meteo   Home Assistant  GitHub API
                                     (public)     (homelab, via   (PAT held in
                                                  HTTPS tunnel;   Apigee KVM,
                                                  LLAT held in    never in MCP
                                                  Apigee KVM)     server)
```

### Key design decisions

1. **Credential separation.** The MCP server holds only Apigee credentials (API key per agent identity). Backend secrets (Home Assistant long-lived access token, GitHub PAT) live in Apigee **Key Value Maps (KVM)** and are injected by an `AssignMessage` policy on the way to the target. If the agent or MCP server is compromised, no backend secret leaks.
2. **Agent identity = Apigee Developer App.** Create two apps: `agent-reader` (read-only product) and `agent-operator` (read+write product). Swapping one env var in the MCP server switches identity — this makes scope enforcement testable.
3. **Scopes via API Products.** Products bundle proxies + operations: `tools-readonly` (GET-only operations on all proxies), `tools-operator` (adds POST on `ha-v1` services and GitHub writes). Apigee enforces operation-level (path + verb) authorization natively via product operations — use that before writing custom policies.
4. **Fail closed.** Any policy error → 4xx/5xx with a sanitized error body (no stack traces, no backend hostnames).
5. **Everything as code.** Proxy bundles, products, KVM entries (except secret values), and test scripts live in a git repo. Deploy with `apigeecli`. No console-clicking after Milestone 1 (console is for learning/inspection only).

### Repo layout

```
agent-airlock/
├── README.md
├── .env.example              # APIGEE_ORG, APIGEE_ENV, APIGEE_HOST, AGENT_API_KEY
├── proxies/
│   ├── weather-v1/apiproxy/  # standard Apigee bundle layout
│   ├── ha-v1/apiproxy/
│   └── github-v1/apiproxy/
├── config/
│   ├── products.json         # tools-readonly, tools-operator
│   ├── developers.json
│   └── apps.json
├── mcp-server/
│   ├── server.py             # FastMCP server
│   ├── requirements.txt
│   └── .env.example
├── scripts/
│   ├── provision.sh          # create products/developers/apps/KVMs via apigeecli
│   ├── deploy.sh             # import + deploy all proxies
│   └── smoke.sh              # curl-based acceptance tests, exits non-zero on failure
└── tests/
    └── test_gateway.py       # pytest: security & policy behavior tests
```

---

## 2. Prerequisites (verify before Milestone 0)

- Google Cloud project with billing enabled. Apigee X **evaluation** org or **Pay-as-you-go** provisioning (verify current trial terms at https://cloud.google.com/apigee/docs — provisioning steps change; do not rely on cached knowledge).
- `gcloud` CLI authenticated; `apigeecli` installed (https://github.com/apigee/apigeecli).
- Python 3.11+, `pip install fastmcp requests pytest`.
- Home Assistant reachable over HTTPS from the internet (existing tunnel or reverse proxy). Create a **long-lived access token** in HA user profile. NOTE FOR EXECUTING AGENT: ask the human to create/supply this token and the HA URL; never generate or guess credentials.
- GitHub fine-grained PAT scoped to one test repo, issues read/write. Ask the human to supply it.
- Open-Meteo needs no key (that's why it's the first backend).

---

## 3. Milestones

Conventions for every milestone:
- **Definition of Done (DoD)** = all acceptance tests pass via `scripts/smoke.sh` (append new tests each milestone; old tests must keep passing — treat as regression suite).
- Commit at the end of each milestone with message `M<n>: <summary>`.
- If a step fails, capture the Apigee debug session (Trace) output before changing anything.

### Milestone 0 — Provision & baseline (est. 1 session)

**Goal:** Working Apigee org, CLI access, empty repo scaffolded.

Tasks:
1. Provision Apigee eval org (or confirm existing). Record `APIGEE_ORG`, `APIGEE_ENV` (use `eval`/`dev`), and the environment group hostname `APIGEE_HOST`.
2. Verify control plane access: `apigeecli organizations get -o $APIGEE_ORG` returns JSON.
3. Scaffold repo layout above; write `.env.example`; init git.

Acceptance tests:
- [ ] `apigeecli environments list -o $APIGEE_ORG` lists the target env.
- [ ] `curl https://$APIGEE_HOST/` returns an Apigee-served response (404 is fine — proves routing works).

### Milestone 1 — First proxy: weather passthrough + API key (est. 1 session)

**Goal:** `weather-v1` proxy fronting Open-Meteo, locked with an API key.

Tasks:
1. Build proxy bundle `weather-v1`, basepath `/weather/v1`, target `https://api.open-meteo.com`. Expose one conditional flow: `GET /forecast` → target `/v1/forecast`, passing query params through.
2. Add `VerifyAPIKey` policy on the request preflow (key in `x-api-key` header).
3. Create API product `tools-readonly` (operation: `weather-v1`, path `/forecast`, verb GET), developer `agents@local`, app `agent-reader`. Store the app's consumer key as `AGENT_READER_KEY`.
4. `scripts/deploy.sh` imports + deploys; `scripts/provision.sh` creates product/dev/app idempotently.

Acceptance tests:
- [ ] No key → HTTP 401.
- [ ] Bad key → 401.
- [ ] Valid key on `GET /weather/v1/forecast?latitude=43.7&longitude=-79.4&current=temperature_2m` → 200 with JSON containing `current.temperature_2m`.

### Milestone 2 — Second identity & scope enforcement (est. 1 session)

**Goal:** Prove product-level authorization: two agents, different rights.

Tasks:
1. Create product `tools-operator` (superset of readonly ops; will gain write ops in M5). Create app `agent-operator` attached to it.
2. Attach `agent-reader` ONLY to `tools-readonly`.
3. Add a second operation to `weather-v1`: `GET /archive` (Open-Meteo historical endpoint) but put it ONLY in `tools-operator`'s operation list.

Acceptance tests:
- [ ] `agent-reader` key on `/forecast` → 200.
- [ ] `agent-reader` key on `/archive` → 403 (operation not in product).
- [ ] `agent-operator` key on `/archive` → 200.

### Milestone 3 — Traffic protection: SpikeArrest + Quota (est. 1 session)

**Goal:** A runaway agent loop cannot hammer a backend or blow a budget.

Tasks:
1. Add `SpikeArrest` (e.g., `10ps`) to `weather-v1` request preflow.
2. Add `Quota` policy: 100 requests/hour, identified by `client_id` (per-app, not global) — read quota settings from the API product so limits are product-managed.
3. Sanitize fault responses: add a `FaultRules`/`AssignMessage` that returns `{"error": "<code>", "message": "<safe text>"}` — no Apigee internals.

Acceptance tests:
- [ ] Burst of 50 requests in 1s: some return 429 (SpikeArrest), body is the sanitized JSON.
- [ ] Loop of 101 requests within the hour on a fresh app: request 101 → 429 with quota-exceeded body.
- [ ] `pytest tests/test_gateway.py -k traffic` passes (script the two cases above).

### Milestone 4 — Payload security: threat protection + redaction (est. 1–2 sessions)

**Goal:** Malformed/hostile payloads rejected; secrets/PII stripped from responses before they reach the agent's context.

Tasks:
1. Add `JSONThreatProtection` (sane limits: container depth ~10, entry count ~200) on any proxy accepting bodies (prep for M5; apply to weather too for uniformity — GETs skip it via condition).
2. Write a JavaScript response policy `redact.js`: walk the response JSON and (a) drop keys matching `token|secret|password|api_key|authorization` (case-insensitive), (b) mask email addresses. Unit-test the JS logic locally with Node before deploying.
3. Add a `RegularExpressionProtection` policy on request query/body for classic injection patterns (`<script`, `' OR 1=1`, etc.) — return 400.

Acceptance tests:
- [ ] Request with a 50-level-deep JSON body → 400.
- [ ] Request containing `?q='%20OR%201=1` → 400.
- [ ] A mock response containing `{"access_token": "abc", "email": "a@b.com"}` (use a test flow or the M5 HA proxy) reaches the client with `access_token` removed and email masked.

### Milestone 5 — Home Assistant proxy: fine-grained control + KVM credential injection (est. 2 sessions)

**Goal:** The centerpiece. Agent can read HA state; only the operator identity can call services; HA's token never leaves Apigee.

Tasks:
1. Create encrypted KVM `backend-secrets` in the env. Add entry `ha_token` (value supplied by human at runtime — provision script must read it from an env var, never hardcode, never commit).
2. Build `ha-v1` proxy, basepath `/ha/v1`, target = HA URL. Flows:
   - `GET /states` and `GET /states/{entity_id}` → HA `/api/states...` — in `tools-readonly` product.
   - `POST /services/{domain}/{service}` → HA `/api/services/...` — in `tools-operator` product ONLY.
   - Everything else → `RaiseFault` 404 (explicit allowlist; do not passthrough unknown paths).
3. `KeyValueMapOperations` (Get) + `AssignMessage`: set `Authorization: Bearer {ha_token}` on the target request. Strip any client-supplied `Authorization` header first.
4. Apply the M3 traffic policies and M4 payload policies (make them shared flows now — refactor `weather-v1` to use the same shared flow; this is the idiomatic Apigee pattern and worth learning).
5. Restrict `POST /services` further: only allow domains `light`, `switch`, `scene` via a condition; `RaiseFault` 403 otherwise (so even the operator agent can't call `homeassistant.restart`).

Acceptance tests:
- [ ] `agent-reader`: `GET /ha/v1/states` → 200, and response contains entities.
- [ ] `agent-reader`: `POST /ha/v1/services/light/turn_on` → 403.
- [ ] `agent-operator`: same POST with `{"entity_id": "light.<test_entity>"}` → 200 and the light actually toggles (human confirms once).
- [ ] `agent-operator`: `POST /ha/v1/services/homeassistant/restart` → 403.
- [ ] `GET /ha/v1/config` (not allowlisted) → 404.
- [ ] Client sends its own `Authorization: Bearer fake` → backend still called with the KVM token (verify via Trace), response normal.
- [ ] Grep the deployed bundle and repo: HA token appears nowhere.

### Milestone 6 — MCP server + agent integration (est. 1–2 sessions)

**Goal:** Claude Code drives the tools; only route is through Apigee.

Tasks:
1. Implement `mcp-server/server.py` with FastMCP, stdio transport. Tools:
   - `get_weather(latitude, longitude)` → `GET /weather/v1/forecast`
   - `ha_get_states(entity_id: str | None)` → `GET /ha/v1/states[/entity_id]`
   - `ha_call_service(domain, service, entity_id)` → `POST /ha/v1/services/...`
   - Each tool: raise a clear error string on 401/403/429 so the agent can explain refusals to the user (e.g., "Gateway denied: your identity lacks this scope").
2. Config via env: `APIGEE_HOST`, `AGENT_API_KEY`. No other secrets present — assert at startup that no `HA_TOKEN`/`GITHUB_TOKEN` env vars exist (fail fast if someone tries to bypass the gateway).
3. Register in Claude Code (Windows): add stdio server entry to MCP config. Document the exact JSON in README.
4. Run two sessions: one with `AGENT_READER_KEY`, one with `AGENT_OPERATOR_KEY`.

Acceptance tests:
- [ ] In Claude Code with reader key: "what's the temperature in the living room?" → agent calls `ha_get_states`, answers correctly.
- [ ] Same session: "turn on the office light" → tool returns scope-denied error; agent relays the refusal (does not crash or hallucinate success).
- [ ] With operator key: same request succeeds.
- [ ] `netstat`/proxy log check: MCP server made zero connections to the HA host directly — all traffic to `$APIGEE_HOST`.

### Milestone 7 — Audit, monitoring & analysis (est. 1–2 sessions)

**Goal:** Answer "what did the agent do, when, and was anything anomalous?" from logs/analytics alone.

Tasks:
1. Add `MessageLogging` (or `DataCapture` + custom analytics variables) to the shared flow: log timestamp, `client_id` (agent identity), proxy, path, verb, status, latency, and — for `ha-v1` POSTs — the domain/service called. Send to Cloud Logging.
2. Create a Cloud Logging log-based metric: count of `ha-v1` service calls per agent per hour; an alert if > 20/hour.
3. In Apigee Analytics (or a custom report), build views: requests per app, error rate per proxy, p95 latency per target.
4. Write `tests/audit_replay.py`: run a scripted 10-call agent session, then query Cloud Logging API and reconstruct the exact sequence of tool calls with identities.

Acceptance tests:
- [ ] Every request from M6's sessions is findable in Cloud Logging with the correct agent identity.
- [ ] `audit_replay.py` reconstructs the scripted session 10/10 calls, in order.
- [ ] Trigger the alert by looping 25 service calls; alert fires.
- [ ] Sanity: response bodies with redacted fields are logged post-redaction (no secrets in logs).

### Milestone 8 (stretch) — GitHub proxy + hardening

- `github-v1` proxy with PAT in KVM, operations: `GET /repos/{owner}/{repo}/issues` (readonly product), `POST .../issues` (operator product). Add `gh_list_issues` / `gh_create_issue` MCP tools.
- Replace API keys with OAuth 2.0 client-credentials: Apigee as authorization server (`OAuthV2` policy), MCP server exchanges key/secret for a bearer token with scopes; enforce `VerifyAccessToken` + scope checks. This is the "token exchange airlock" pattern.
- Optional: mTLS or IP allowlist from Apigee to the HA tunnel so HA only accepts gateway traffic.

---

## 4. Threat-model checklist (final review)

Walk this after M7; each row must cite the mechanism and the passing test:

| Threat | Mitigation | Verified by |
|---|---|---|
| Stolen MCP server config | Only Apigee key leaks; revoke app in seconds; backend secrets in KVM | M5 grep test |
| Runaway agent loop | SpikeArrest + per-app Quota | M3 tests |
| Prompt-injected destructive call | Verb/path/domain allowlist; operator-only writes; `restart` blocked | M5 tests |
| Secret leakage into agent context | Response redaction shared flow | M4 test |
| Unaudited actions | MessageLogging per identity + replay test | M7 tests |
| Payload attacks | JSONThreatProtection + regex protection | M4 tests |

## 5. Notes for the executing agent

- Prefer `apigeecli` + declarative bundles over console edits; the console Trace/Debug tool is your primary diagnostic.
- Apigee policy XML is picky: policy `name` attributes must match filenames and step references exactly. Validate by importing before debugging behavior.
- When a test fails, start a Debug session, re-run the single failing curl, and read the policy-by-policy execution before editing anything.
- Never print or commit: HA token, GitHub PAT, consumer secrets. Consumer *keys* (API keys) may appear in local `.env` only.
- Ask the human before: creating GCP billable resources beyond the eval org, sending any HA service call the first time, and any step requiring credentials.
