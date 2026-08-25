"""One factory, two agents, and a startup contract that mirrors the MCP server.

Both agents in this directory are the same code with a different key. That is
deliberate: the difference between the reader and the operator is *not* in their
prompts or their tool lists, it is in which Apigee API Product their consumer key
belongs to. The reader agent physically cannot create a GitHub issue no matter
how it is prompted, because the gateway refuses the call -- and the refusal lands
in the audit log with the agent's name on it.

Two planes, one credential:

  * Model plane -- LiteLLM's OpenAI driver pointed at ``/llm/v1`` on the gateway,
    authenticating with the agent's consumer key. The real OpenRouter credential
    lives in an Apigee KVM and is injected there; this process has never seen it.
  * Tool plane -- an ADK MCPToolset launching the existing ``mcp-server``, which
    is itself only a client of the gateway. Same key, same identity, so the model
    calls and the tool calls read back as one session in the audit.

The module is arranged so that everything above ``build_root_agent`` is pure
configuration with no ADK import in it. The properties most worth testing here
are refusals -- what this refuses to start with -- and a test that could only run
with the full agent stack installed is a test that will be skipped on the machine
where it matters.

Environment (mirrors mcp-server/server.py exactly, plus the model plane):

    APIGEE_HOST         bare hostname of the gateway, e.g. <lb-ip>.nip.io
    AGENT_READER_KEY    the reader's consumer key   \\ either the identity-specific
    AGENT_OPERATOR_KEY  the operator's consumer key /  name or AGENT_API_KEY
    AIRLOCK_AGENT_MODEL optional; defaults to the first of LLM_ALLOWED_MODELS
"""

from __future__ import annotations

import os
import shutil
import sys
from dataclasses import dataclass

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MCP_DIR = os.path.join(ROOT, "mcp-server")

# Set before anything can import litellm, because litellm's __init__ runs
#
#     if os.getenv("LITELLM_MODE", "DEV") == "DEV": dotenv.load_dotenv()
#
# and load_dotenv() walks up from site-packages until it finds a .env -- which,
# for an agent run out of this repository, is the .env at ROOT: the one
# provision.sh reads to load the KVM, holding OPENROUTER_API_KEY and the GitHub
# PAT. So `import litellm` copies both into this process. That is worse than the
# leak _require_clean was written for: there, someone had exported a credential
# and the check caught them. Here a library reaches out and fetches one, after
# the launcher went to the trouble of stripping it, and if the import happens to
# land after the check it leaves no trace at all -- an agent holding a provider
# key, believing it holds none.
#
# Any value but "DEV" suppresses it. The existing value is deliberately not
# honoured: LITELLM_MODE=DEV in the environment would re-enable exactly this,
# and nothing about this agent has a legitimate reason to ask for it.
os.environ["LITELLM_MODE"] = "PRODUCTION"

# Any of these in the environment means someone has a route to a backend that
# does not pass through the gateway. OPENROUTER_API_KEY and OPENAI_API_KEY are
# the new entries and the sharpest ones: LiteLLM reads OPENAI_API_KEY by itself,
# so a key sitting in the shell would be picked up silently and every model call
# would leave through the front door with no allowlist, no token ceiling, no
# quota and no audit record. Crashing is the only honest response.
FORBIDDEN_ENV = (
    "OPENROUTER_API_KEY",
    "OPENAI_API_KEY",
    "OPENAI_API_BASE",
    "ANTHROPIC_API_KEY",
    "GITHUB_TOKEN",
    "GITHUB_PAT",
    "GH_TOKEN",
    "HA_TOKEN",
    "HOME_ASSISTANT_TOKEN",
    "OPENWEATHER_API_KEY",
    "SLACK_BOT_TOKEN",
    "SLACK_TOKEN",
    "SLACK_APP_TOKEN",
    "SLACK_USER_TOKEN",
    # A Slack incoming webhook URL is not a token but it is a bare capability:
    # holding it is enough to post into a channel with no credential at all.
    "SLACK_WEBHOOK_URL",
)


class ConfigError(RuntimeError):
    """A startup contract violation, phrased for whoever has to fix it."""


@dataclass(frozen=True)
class Settings:
    label: str
    key: str
    base_url: str      # https://<host>
    model: str         # the upstream model id, e.g. google/gemma-4-31b-it:free

    @property
    def llm_base(self) -> str:
        """The OpenAI-compatible base URL. LiteLLM appends /chat/completions."""
        return self.base_url + "/llm/v1"


def _require_clean(env) -> None:
    leaked = [name for name in FORBIDDEN_ENV if env.get(name)]
    if leaked:
        raise ConfigError(
            "refusing to start: backend credentials are present in the environment "
            f"({', '.join(leaked)}). This agent must reach both models and tools "
            "only through the Apigee gateway, which injects credentials itself. "
            "If this process can reach a real credential the airlock is already "
            "open. Unset them."
        )


def _require_host(env) -> str:
    host = (env.get("APIGEE_HOST") or "").strip()
    if not host:
        raise ConfigError("APIGEE_HOST is not set (e.g. <lb-ip>.nip.io)")
    # A scheme or a path here would let configuration redirect every model call
    # and every tool call somewhere else -- which is the entire attack this
    # architecture exists to prevent, arriving through the config file instead of
    # through the prompt. Require a bare host and build the URLs ourselves.
    if "://" in host or "/" in host:
        raise ConfigError(f"APIGEE_HOST must be a bare hostname, got {host!r}")
    return host


def _require_key(env, *names: str) -> str:
    """The agent's consumer key, by identity-specific name or the generic one.

    Both spellings are accepted because the two deployment shapes want different
    ones. `adk run adk-agents/airlock_reader` is one agent in one process and
    AGENT_API_KEY reads naturally; `adk web` offers both agents from a single
    process, where one generic name cannot mean two different keys. Preferring
    the specific name keeps the second case honest instead of silently giving
    both agents whichever key was exported last.
    """
    for name in names:
        value = (env.get(name) or "").strip()
        if value:
            return value
    return ""


def settings(label: str, key_var: str, env=None) -> Settings:
    """The whole startup contract, as a value. Raises ConfigError, never exits."""
    env = os.environ if env is None else env
    _require_clean(env)
    host = _require_host(env)

    key = _require_key(env, key_var, "AGENT_API_KEY")
    if not key:
        raise ConfigError(
            f"{key_var} is not set (a gateway consumer key from .env -- not a "
            "backend token; the gateway holds those)"
        )

    model = (env.get("AIRLOCK_AGENT_MODEL") or "").strip()
    if not model:
        # The first allowlisted model, which is the same rule the smoke suite
        # follows, so the agent spends its budget on the model the tests price.
        model = ((env.get("LLM_ALLOWED_MODELS") or "").split(",") + [""])[0].strip()
    if not model:
        raise ConfigError(
            "no model configured: set AIRLOCK_AGENT_MODEL, or LLM_ALLOWED_MODELS "
            "to the gateway's allowlist. Asking for a model the gateway does not "
            "allowlist gets a 403, not an answer."
        )

    return Settings(label=label, key=key, base_url=f"https://{host}", model=model)


def mcp_child_env(settings: Settings, env=None) -> dict:
    """The environment the MCP server subprocess is launched with.

    Filtered rather than inherited. The check above runs once, at import; this
    runs at every launch, and between the two someone's tooling can perfectly
    well have put a token into the environment. The child does its own check and
    would refuse to start -- but a subprocess that dies at spawn time surfaces to
    the model as "the tools are broken", so it is cleaner not to hand it the
    thing it would have to refuse.
    """
    env = os.environ if env is None else env
    child = {k: v for k, v in env.items() if k not in FORBIDDEN_ENV}
    child["APIGEE_HOST"] = settings.base_url.split("://", 1)[1]
    child["AGENT_API_KEY"] = settings.key
    child["AGENT_LABEL"] = settings.label
    return child


def mcp_command() -> list:
    """How to launch the MCP server: uv if it is on PATH, else this interpreter.

    uv is preferred because it resolves the server's own lockfile, which is the
    documented way to run it and the only way its dependencies are guaranteed
    present. The fallback exists so a machine without uv gets a legible import
    error from Python rather than an opaque "command not found" from the toolset.
    """
    uv = shutil.which("uv")
    if uv:
        return [uv, "run", "--directory", MCP_DIR, "server.py"]
    return [sys.executable, os.path.join(MCP_DIR, "server.py")]


# --------------------------------------------------------------------- ADK glue

INSTRUCTION = """You are {label}, an agent that reaches the outside world only
through a policy gateway.

Your tools cover weather lookups, GitHub issues on one allowlisted repository,
and Slack messages in a small set of allowlisted channels.
{scope}

Slack channels are addressed by ID, never by name. You cannot list channels and
you cannot turn "#ops" into an ID -- if the user names a channel, ask them for
its ID rather than guessing one, because a guess will be refused and the refusal
will be logged as an attempt.

When a tool comes back with a refusal -- a 403, "not scoped", "not allowlisted"
-- that is the gateway enforcing policy deliberately. Report it to the user in
plain language and say what was refused. Do not retry it, do not rephrase it,
and do not look for another route: there is no other route, and trying to find
one is the behaviour the gateway is watching for.

Never ask the user for an API key, a token, or a URL to call. You do not need
them and you cannot use them."""

READER_SCOPE = (
    "You can look things up but you cannot change anything. Creating or "
    "commenting on an issue, and posting to Slack, are outside your scope and "
    "will be refused; if the user wants that, tell them it needs the operator "
    "identity. You may read recent messages in an allowlisted Slack channel."
)

OPERATOR_SCOPE = (
    "You may create issues on the allowlisted repository and post messages to "
    "allowlisted Slack channels. Everything you write is attributed to your "
    "identity in an audit log a human reads, and a Slack message is read by "
    "people the moment it lands -- so write what a human would be glad to find: "
    "clear, specific, and worth the interruption. Show the user the exact text "
    "before you post it."
)


def build_root_agent(label: str, key_var: str, scope: str, name: str):
    """The ADK agent. Imports ADK lazily so the contract above stays testable."""
    from google.adk.agents import Agent
    from google.adk.models.lite_llm import LiteLlm

    try:  # ADK moved these between releases; both spellings are in the wild.
        from google.adk.tools.mcp_tool import MCPToolset, StdioConnectionParams
        from mcp import StdioServerParameters
    except ImportError:  # pragma: no cover - depends on the installed ADK
        from google.adk.tools.mcp_tool.mcp_toolset import (  # type: ignore
            MCPToolset,
            StdioServerParameters,
        )
        StdioConnectionParams = None  # type: ignore

    cfg = settings(label, key_var)
    server = StdioServerParameters(
        command=mcp_command()[0],
        args=mcp_command()[1:],
        env=mcp_child_env(cfg),
    )
    if StdioConnectionParams is not None:
        toolset = MCPToolset(connection_params=StdioConnectionParams(
            server_params=server, timeout=60))
    else:  # pragma: no cover - older ADK
        toolset = MCPToolset(connection_params=server)

    return Agent(
        name=name,
        # The "openai/" prefix selects LiteLLM's OpenAI-compatible driver; the
        # rest of the string is the model id the gateway's allowlist checks, and
        # it travels unchanged. api_key is the consumer key: the gateway strips
        # it and injects the real upstream credential.
        model=LiteLlm(model="openai/" + cfg.model,
                      api_base=cfg.llm_base,
                      api_key=cfg.key),
        instruction=INSTRUCTION.format(label=label, scope=scope),
        description=f"Agent Airlock {label}: gateway-mediated weather and GitHub access.",
        tools=[toolset],
    )
