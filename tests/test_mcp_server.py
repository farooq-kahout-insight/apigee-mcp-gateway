"""End-to-end tests for the MCP server, driven over real stdio.

These spawn the server as a subprocess and speak MCP to it rather than importing
the module and calling the tool functions directly. That distinction is the
point: the properties under test are properties of the *process* -- what it
refuses to start with, which credential it carries, what it does with a gateway
refusal -- and importing it would bypass every one of them.

Needs the `mcp` client library, which lives in the server's own virtualenv:

    uv run --directory mcp-server --with pytest --with requests python -m pytest tests/test_mcp_server.py

Tests that need a live gateway skip rather than fail when .env has no agent keys.
"""

import asyncio
import os
import subprocess
import sys

import pytest

pytest.importorskip(
    "mcp",
    reason="mcp client not installed; see the module docstring for the uv command",
)
from mcp import Client, StdioServerParameters  # noqa: E402
from mcp.client.stdio import get_default_environment, stdio_client  # noqa: E402

from conftest import ENV  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER_DIR = os.path.join(ROOT, "mcp-server")
SERVER = os.path.join(SERVER_DIR, "server.py")
HOST = ENV.get("APIGEE_HOST", "")

# A real, public repository that is deliberately not the allowlisted one, so a
# refusal proves the allowlist fired rather than the request merely 404ing.
OTHER_REPO = "octocat/Hello-World"


def _child_env(**overrides):
    """The environment the server subprocess gets.

    Built from mcp's own minimal inherited set rather than from os.environ, so a
    GITHUB_TOKEN sitting in the developer's shell cannot quietly change what
    these tests exercise. An override of "" means "unset this".
    """
    env = get_default_environment()
    env.update(overrides)
    return {k: v for k, v in env.items() if v != ""}


def _params(key, label="test-agent"):
    return StdioServerParameters(
        command=sys.executable,
        args=[SERVER],
        env=_child_env(APIGEE_HOST=HOST, AGENT_API_KEY=key, AGENT_LABEL=label),
        cwd=SERVER_DIR,
    )


def _run(coro):
    """Run one async body. Avoids a pytest-asyncio dependency for a handful of tests."""
    return asyncio.run(coro)


def _call(key, name, args, label="test-agent"):
    async def go():
        async with Client(stdio_client(_params(key, label))) as client:
            return await client.call_tool(name, args)

    return _run(go())


def _text(result):
    """Flatten a tool result to searchable text, success or error alike."""
    parts = [getattr(b, "text", "") or "" for b in (result.content or [])]
    structured = getattr(result, "structured_content", None)
    if structured:
        parts.append(str(structured))
    return "\n".join(parts)


def _reader():
    key = ENV.get("AGENT_READER_KEY")
    if not key:
        pytest.skip("AGENT_READER_KEY unset; run scripts/provision.sh")
    return key


def _operator():
    key = ENV.get("AGENT_OPERATOR_KEY")
    if not key:
        pytest.skip("AGENT_OPERATOR_KEY unset; run scripts/provision.sh")
    return key


# --------------------------------------------------------------- startup guards


@pytest.mark.parametrize(
    "overrides,expected",
    [
        ({"GITHUB_TOKEN": "ghp_pretend"}, "backend credentials are present"),
        ({"GITHUB_PAT": "github_pat_pretend"}, "backend credentials are present"),
        ({"HA_TOKEN": "pretend"}, "backend credentials are present"),
        ({"APIGEE_HOST": ""}, "APIGEE_HOST is not set"),
        ({"APIGEE_HOST": "https://example.test"}, "must be a bare hostname"),
        ({"APIGEE_HOST": "example.test/path"}, "must be a bare hostname"),
        ({"AGENT_API_KEY": ""}, "AGENT_API_KEY is not set"),
    ],
)
def test_startup_refuses_bad_configuration(overrides, expected):
    """A misconfigured server must die loudly rather than run in a degraded mode.

    The credential cases are the load-bearing ones: the design rests on this
    process having no way to reach a backend directly, so a backend token in its
    environment means the gateway is being bypassed. Failing to start is the
    desired outcome; a bypass that works is far worse than one that crashes.
    """
    env = _child_env(APIGEE_HOST=HOST or "gateway.invalid", AGENT_API_KEY="dummy-key")
    for key, value in overrides.items():
        if value == "":
            env.pop(key, None)
        else:
            env[key] = value

    proc = subprocess.run(
        [sys.executable, SERVER],
        env=env,
        cwd=SERVER_DIR,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 2, f"expected exit 2, got {proc.returncode}: {proc.stderr}"
    assert expected in proc.stderr, proc.stderr


# ------------------------------------------------------------------- tool shape


def test_tools_are_exactly_the_expected_set():
    """The tool surface is the attack surface, so assert it exactly rather than loosely."""

    async def go():
        async with Client(stdio_client(_params(_reader()))) as client:
            return await client.list_tools()

    names = sorted(t.name for t in _run(go()).tools)
    assert names == ["get_weather", "gh_create_issue", "gh_list_issues", "whoami"]


def test_whoami_never_returns_the_key():
    key = _reader()
    text = _text(_call(key, "whoami", {}, label="reader"))
    assert "reader" in text
    assert key not in text


# ---------------------------------------------------------------------- weather


def test_get_weather_reaches_the_backend_through_the_gateway():
    result = _call(_reader(), "get_weather", {"latitude": 43.7, "longitude": -79.4})
    assert not result.is_error, _text(result)
    assert "temperature_2m" in _text(result)


@pytest.mark.parametrize(
    "args,expected",
    [
        ({"latitude": 991.0, "longitude": 0.0}, "latitude"),
        ({"latitude": 0.0, "longitude": -900.0}, "longitude"),
        ({"latitude": 0.0, "longitude": 0.0, "forecast_days": 99}, "forecast_days"),
    ],
)
def test_get_weather_validates_arguments_before_any_request_leaves(args, expected):
    result = _call(_reader(), "get_weather", args)
    assert result.is_error
    assert expected in _text(result)


# ----------------------------------------------------------------------- github


def test_reader_cannot_create_an_issue_and_is_told_why():
    """A refusal must arrive as a legible message, not a crash or a stack trace.

    An agent handed an opaque failure retries or invents a workaround; one told
    "this is a policy decision" can relay it to the user and stop.
    """
    result = _call(
        _reader(),
        "gh_create_issue",
        {"repo": OTHER_REPO, "title": "should not be created"},
        label="reader",
    )
    assert result.is_error
    text = _text(result)
    assert "denied" in text.lower()
    assert "reader" in text
    assert "do not retry" in text.lower()


def test_operator_is_still_confined_to_the_allowlisted_repository():
    """Operator scope is about which verbs are allowed, not which repo the PAT is spent on."""
    allowed = ENV.get("GITHUB_ALLOWED_REPO", "")
    if allowed.lower() == OTHER_REPO.lower():
        pytest.skip("the allowlisted repo is the one used here as the negative control")

    result = _call(_operator(), "gh_list_issues", {"repo": OTHER_REPO}, label="operator")
    assert result.is_error
    text = _text(result)
    assert "denied" in text.lower()
    # The refusal must not confirm what was asked for: an agent probing for a
    # repository's existence should learn nothing from the error text.
    assert "octocat" not in text.lower()


@pytest.mark.parametrize("repo", ["not-a-repo", "owner/", "/name", "a/b/c", "", "  "])
def test_malformed_repo_is_rejected_locally(repo):
    """A cheap client-side shape check. The gateway allowlist remains the real control."""
    result = _call(_reader(), "gh_list_issues", {"repo": repo})
    assert result.is_error
    assert "owner/name" in _text(result)


@pytest.mark.parametrize("repo", ["owner/name?x=1", "owner/name#frag", "owner/na&me"])
def test_repo_cannot_smuggle_query_or_fragment_syntax(repo):
    """The repo argument becomes part of a URL path; it must not be able to escape it."""
    result = _call(_reader(), "gh_list_issues", {"repo": repo})
    assert result.is_error
    assert "not allowed" in _text(result)
