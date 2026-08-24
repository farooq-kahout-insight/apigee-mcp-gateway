"""The ADK agents' startup contract.

These test refusals, and they import only the factory's configuration half --
never ADK, never LiteLLM. That is on purpose. The properties worth asserting
here are the ones that keep a credential out of the agent process, and a test
that needs the full agent stack installed is a test that gets skipped on the
machine where somebody has just exported OPENAI_API_KEY to make something work.

    python -m pytest tests/test_adk_agents.py
"""

import importlib
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AGENTS = os.path.join(ROOT, "adk-agents")
sys.path.insert(0, AGENTS)

from airlock_common import factory  # noqa: E402

HOST = "YOUR_LB_IP.nip.io"
GOOD = {
    "APIGEE_HOST": HOST,
    "AGENT_READER_KEY": "reader-consumer-key",
    "LLM_ALLOWED_MODELS": "google/gemma-4-31b-it:free,z-ai/glm-5.2:free",
}


def env(**overrides):
    """A clean environment plus overrides. A value of None removes the key."""
    merged = dict(GOOD)
    merged.update(overrides)
    return {k: v for k, v in merged.items() if v is not None}


# --------------------------------------------------------------- the refusals

@pytest.mark.parametrize("leaked", [
    "OPENROUTER_API_KEY",   # the upstream model credential the gateway injects
    "OPENAI_API_KEY",       # LiteLLM reads this one by itself, silently
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "HA_TOKEN",
])
def test_refuses_to_start_with_a_backend_credential_in_the_environment(leaked):
    with pytest.raises(factory.ConfigError) as caught:
        factory.settings("agent-reader", "AGENT_READER_KEY", env(**{leaked: "x"}))
    assert leaked in str(caught.value)


def test_openai_api_key_is_not_merely_ignored():
    """The sharp case, stated as its own test because it fails silently.

    LiteLLM picks OPENAI_API_KEY up from the environment on its own. An agent
    that starts anyway would keep working -- and every model call would leave
    through the front door, with no allowlist, no token ceiling, no quota and no
    audit record, while the gateway's dashboards showed a quiet day.
    """
    with pytest.raises(factory.ConfigError):
        factory.settings("agent-reader", "AGENT_READER_KEY",
                         env(OPENAI_API_KEY="sk-live-whatever"))


def test_importing_the_factory_stops_litellm_reading_the_repo_env():
    """The leak the checks above cannot catch, because it arrives after them.

    litellm's __init__ calls dotenv.load_dotenv() unless LITELLM_MODE holds
    something other than "DEV", and load_dotenv walks up from site-packages
    until it finds a .env -- which, for an agent run out of this repository, is
    the one provision.sh reads to fill the KVM. So `import litellm` puts
    OPENROUTER_API_KEY and the GitHub PAT into the process on its own, whatever
    the launcher unset. If that import lands after settings() the agent holds a
    provider credential, every check has passed, and nothing anywhere says so.
    """
    assert os.environ.get("LITELLM_MODE") not in (None, "", "DEV")


def test_a_preset_dev_mode_does_not_survive_the_import():
    """DEV is the one value that re-enables the load, so it is the one value the
    module must refuse to honour -- and LITELLM_MODE is exactly the sort of
    variable somebody exports once to debug something and never unsets."""
    before = os.environ.get("LITELLM_MODE")
    os.environ["LITELLM_MODE"] = "DEV"
    try:
        importlib.reload(factory)
        assert os.environ["LITELLM_MODE"] != "DEV"
    finally:
        if before is None:
            os.environ.pop("LITELLM_MODE", None)
        else:
            os.environ["LITELLM_MODE"] = before


@pytest.mark.parametrize("host", [
    "https://YOUR_LB_IP.nip.io",
    "YOUR_LB_IP.nip.io/llm/v1",
    "evil.example.com/../",
])
def test_refuses_a_host_that_is_not_a_bare_hostname(host):
    """Config is an attack surface too.

    A scheme or a path here redirects every model call and every tool call
    somewhere else -- the exact thing this architecture exists to prevent,
    arriving through the config file rather than through the prompt.
    """
    with pytest.raises(factory.ConfigError) as caught:
        factory.settings("agent-reader", "AGENT_READER_KEY", env(APIGEE_HOST=host))
    assert "bare hostname" in str(caught.value)


def test_refuses_without_a_host():
    with pytest.raises(factory.ConfigError):
        factory.settings("agent-reader", "AGENT_READER_KEY", env(APIGEE_HOST=None))


def test_refuses_without_a_key():
    with pytest.raises(factory.ConfigError) as caught:
        factory.settings("agent-reader", "AGENT_READER_KEY",
                         env(AGENT_READER_KEY=None))
    assert "AGENT_READER_KEY" in str(caught.value)


def test_refuses_without_an_allowlisted_model():
    """Better than a 403 at the first question the user asks."""
    with pytest.raises(factory.ConfigError):
        factory.settings("agent-reader", "AGENT_READER_KEY",
                         env(LLM_ALLOWED_MODELS=None))


# ------------------------------------------------------------ the two agents

def test_each_identity_takes_its_own_key():
    reader = factory.settings("agent-reader", "AGENT_READER_KEY",
                              env(AGENT_OPERATOR_KEY="operator-consumer-key"))
    operator = factory.settings("agent-operator", "AGENT_OPERATOR_KEY",
                                env(AGENT_OPERATOR_KEY="operator-consumer-key"))
    assert reader.key == "reader-consumer-key"
    assert operator.key == "operator-consumer-key"
    # The label is what the gateway's audit attributes the call to, so a
    # mismatch here would show one agent's work under the other's name.
    assert (reader.label, operator.label) == ("agent-reader", "agent-operator")


def test_the_identity_specific_key_beats_the_generic_one():
    """`adk web` serves both agents from one process.

    One generic AGENT_API_KEY cannot mean two different keys there, and the
    failure mode if the generic name won would be quiet: both agents would run
    happily under whichever identity was exported last, and the audit would
    record a session that never happened.
    """
    cfg = factory.settings("agent-reader", "AGENT_READER_KEY",
                           env(AGENT_API_KEY="generic-key"))
    assert cfg.key == "reader-consumer-key"


def test_the_generic_key_still_works_for_a_single_agent_process():
    cfg = factory.settings("agent-reader", "AGENT_READER_KEY",
                           env(AGENT_READER_KEY=None, AGENT_API_KEY="generic-key"))
    assert cfg.key == "generic-key"


def test_the_model_defaults_to_the_first_allowlisted_one():
    cfg = factory.settings("agent-reader", "AGENT_READER_KEY", env())
    assert cfg.model == "google/gemma-4-31b-it:free"


def test_an_explicit_model_overrides_the_allowlist_order():
    cfg = factory.settings("agent-reader", "AGENT_READER_KEY",
                           env(AIRLOCK_AGENT_MODEL="z-ai/glm-5.2:free"))
    assert cfg.model == "z-ai/glm-5.2:free"


def test_the_model_plane_points_at_the_gateway():
    cfg = factory.settings("agent-reader", "AGENT_READER_KEY", env())
    assert cfg.llm_base == "https://%s/llm/v1" % HOST


# ------------------------------------------------------- the tool subprocess

def test_the_mcp_child_gets_this_agents_identity():
    cfg = factory.settings("agent-operator", "AGENT_OPERATOR_KEY",
                           env(AGENT_OPERATOR_KEY="operator-consumer-key"))
    child = factory.mcp_child_env(cfg, env(AGENT_OPERATOR_KEY="operator-consumer-key"))
    assert child["APIGEE_HOST"] == HOST
    assert child["AGENT_API_KEY"] == "operator-consumer-key"
    assert child["AGENT_LABEL"] == "agent-operator"


def test_the_mcp_child_is_never_handed_a_backend_credential():
    """Filtered at every launch, not just checked once at import.

    The startup check runs when the module loads; this runs each time the
    toolset spawns the server, and between the two, tooling can perfectly well
    have put a token into the environment. The child would refuse to start on
    its own -- but a subprocess that dies at spawn time reaches the model as
    "the tools are broken", which is a worse thing to debug than a clean env.
    """
    cfg = factory.settings("agent-reader", "AGENT_READER_KEY", env())
    dirty = env(GITHUB_TOKEN="ghp_realtoken", OPENROUTER_API_KEY="sk-or-real")
    child = factory.mcp_child_env(cfg, dirty)
    for name in factory.FORBIDDEN_ENV:
        assert name not in child


def test_the_mcp_server_is_launched_from_this_repository():
    """Not from PATH, and not from wherever the process happens to be running."""
    command = factory.mcp_command()
    assert any("mcp-server" in part for part in command)
    assert os.path.isfile(os.path.join(factory.MCP_DIR, "server.py"))


# ------------------------------------------------------------ what is on disk

@pytest.mark.parametrize("name", ["airlock_reader", "airlock_operator"])
def test_no_credential_or_backend_address_is_baked_into_an_agent(name):
    """The same assertion M6 makes about the MCP server, for the same reason.

    An agent module that carried its own key would put the credential in git and
    make the identity a property of the source rather than of the environment --
    at which point the two agents stop being one code path with two keys, which
    is the only thing making the reader's incapacity trustworthy.
    """
    with open(os.path.join(AGENTS, name, "agent.py"), encoding="utf-8") as handle:
        source = handle.read()
    for needle in ("sk-or-", "ghp_", "github_pat_", "openrouter.ai", "api.github.com",
                   "open-meteo", "nip.io"):
        assert needle not in source, f"{name}/agent.py mentions {needle!r}"
