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

```
Claude Code ──stdio──> mcp-server/server.py ──HTTPS + x-api-key──> Apigee (eval org)
                       (no backend creds)                          │
                                                                   ├─ VerifyAPIKey        identity
                                                                   ├─ API Product         scope
                                                                   ├─ SpikeArrest/Quota   rate
                                                                   ├─ JSONThreatProtection + injection screen
                                                                   ├─ KVM (encrypted)     credential injection
                                                                   ├─ repo allowlist
                                                                   └─ response redaction + fault sanitizing
                                                                   │
                                                          api.open-meteo.com / api.github.com
```

## Layout

| Path | What |
| --- | --- |
| `proxies/weather-v1/` | Open-Meteo forecast + archive, no credential needed |
| `proxies/github-v1/` | GitHub issues; the PAT is fetched from a KVM at target time |
| `sharedflows/sf-inbound-security/` | API key, spike arrest, quota, threat protection, injection screen |
| `sharedflows/sf-outbound-redaction/` | Strips credential-shaped material from responses |
| `sharedflows/sf-fault-sanitizer/` | Every error becomes `{"error","message"}` — no Apigee internals |
| `sharedflows/sf-target-hygiene/` | Removes inbound auth headers before any upstream call |
| `config/products/` | API products — the scope model |
| `config/apps.json` | The two agent identities |
| `scripts/provision.sh` | Idempotent: products, apps, KVMs, keys into `.env` |
| `scripts/deploy.sh` | Bundles and deploys proxies and shared flows |
| `scripts/smoke.sh` | The acceptance suite. `M0`…`M6` filters, cumulative |
| `mcp-server/` | The stdio MCP server |
| `tests/` | pytest + node unit tests, driven by `smoke.sh` |

## Identities

Two agents, two API keys, two API products. The split is the demo: the same
codebase, the same tools, different authority.

| | `agent-reader` (`tools-readonly`) | `agent-operator` (`tools-operator`) |
| --- | --- | --- |
| weather `/forecast` | GET | GET |
| weather `/archive`, `/selftest` | — | GET (+POST on selftest) |
| github issues | GET | GET, POST |
| quota | 100/hour | 100/hour |

Scope is enforced by the API Product, which Apigee evaluates in PreFlow — before
any of the proxy's own logic. A path that is not in the product returns 403
"not scoped" and never reaches the proxy at all. `tools-quotaprobe` (10/hour)
exists only so the quota tests can exhaust a budget cheaply.

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
        "C:\\path\\to\\mcp-secure-gateway\\mcp-server",
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
        "C:\\path\\to\\mcp-secure-gateway\\mcp-server",
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
- no GitHub token literal appears anywhere in tracked files
- the MCP server dies with exit 2 if a backend credential is in its environment

## Deviations from the spec

- **Home Assistant is dropped.** GitHub takes its place as the credential-
  injection backend in M5 and supplies the write-capable tools in M6, so the
  tools are `gh_list_issues` / `gh_create_issue` rather than `ha_get_states` /
  `ha_call_service`.
- Developer email is `agents@agent-airlock.example.com`; Apigee rejects
  `agents@local`.
- The quota test uses a dedicated 10/hour product on a throwaway app instead of
  driving the 101st request through a 100/hour one — same assertion, two orders
  of magnitude less traffic.
