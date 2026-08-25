"""
Agent Airlock MCP server -- stdio transport, FastMCP.

Every tool here is a thin client of the Apigee gateway. That is the whole point:
this process holds one credential (its own gateway API key) and has no idea what
a GitHub token looks like. Scope, rate limits, repository allowlisting, payload
screening and response redaction are all enforced upstream in Apigee, so a bug
or a prompt injection in the agent cannot widen what this process may do.

Two consequences are load-bearing and are enforced below rather than documented:

  * The base URL is fixed to the gateway. No tool takes a URL, a host, or
    anything that becomes one. An agent cannot talk this server into fetching
    an arbitrary address.
  * Backend credentials must not be present in this process at all. If someone
    "helpfully" exports GITHUB_TOKEN to make a failure go away, startup aborts:
    a bypass that works is far worse than one that crashes.

Configuration (environment):
    APIGEE_HOST     hostname of the gateway, e.g. <lb-ip>.nip.io
    AGENT_API_KEY   this agent's gateway key (reader or operator)
    AGENT_LABEL     optional, shown in errors to make multi-identity setups legible
"""

from __future__ import annotations

import os
import sys
from typing import Any

import httpx

# mcp 2.x renamed FastMCP to MCPServer; the decorator-and-docstring model is the
# same. Imported after the standard library so a missing dependency surfaces as
# an ordinary ImportError rather than being confused with a config failure.
from mcp.server import MCPServer

# Names that would indicate someone is trying to reach a backend directly rather
# than through the gateway. Presence of any one of them is a configuration error.
FORBIDDEN_ENV = (
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
    # Not a bearer token, but a Slack incoming webhook URL is a bare capability:
    # anyone holding it can post to a channel with no credential at all, which
    # is exactly the bypass the rest of this list exists to prevent.
    "SLACK_WEBHOOK_URL",
)

TIMEOUT = httpx.Timeout(30.0, connect=10.0)


def _fail(message: str) -> "None":
    print(f"agent-airlock: {message}", file=sys.stderr)
    raise SystemExit(2)


def _startup_checks() -> tuple[str, str, str]:
    leaked = [name for name in FORBIDDEN_ENV if os.environ.get(name)]
    if leaked:
        _fail(
            "refusing to start: backend credentials are present in the environment "
            f"({', '.join(leaked)}). This server must reach backends only through "
            "the Apigee gateway, which injects credentials itself. Unset them."
        )

    host = os.environ.get("APIGEE_HOST", "").strip()
    if not host:
        _fail("APIGEE_HOST is not set (e.g. <lb-ip>.nip.io)")
    # A scheme or path here would let configuration silently redirect every tool
    # call somewhere else; require a bare host and build the URL ourselves.
    if "://" in host or "/" in host:
        _fail(f"APIGEE_HOST must be a bare hostname, got {host!r}")

    key = os.environ.get("AGENT_API_KEY", "").strip()
    if not key:
        _fail("AGENT_API_KEY is not set (a gateway key from .env, not a backend token)")

    return f"https://{host}", key, os.environ.get("AGENT_LABEL", "agent").strip()


BASE_URL, API_KEY, AGENT_LABEL = _startup_checks()
mcp = MCPServer(
    "agent-airlock",
    instructions=(
        "Tools reach weather, GitHub and Slack through a policy gateway. A 403 is a "
        "deliberate refusal, not a transient error: relay it to the user instead "
        "of retrying or looking for another route."
    ),
)


class GatewayError(RuntimeError):
    """Raised with text meant to be read by the model, not by a developer."""


def _explain(response: httpx.Response) -> str:
    """Turn a gateway refusal into something an agent can relay to a human.

    The gateway's own error bodies are already sanitized to {"error","message"},
    so they are safe to surface verbatim. Anything else is summarized rather
    than passed through, in case an upstream ever returns something chattier.
    """
    detail = ""
    try:
        payload = response.json()
        if isinstance(payload, dict):
            detail = str(payload.get("message") or payload.get("error") or "")
    except ValueError:
        pass

    status = response.status_code
    if status == 401:
        return (
            f"Gateway rejected the credential for '{AGENT_LABEL}'. The API key is "
            f"missing, revoked, or wrong. {detail}".strip()
        )
    if status == 403:
        return (
            f"Gateway denied this operation for '{AGENT_LABEL}': the identity is not "
            f"scoped for it, or the target is outside the allowlist. {detail} "
            "This is a policy decision -- do not retry or work around it; tell the "
            "user what was refused."
        ).strip()
    if status == 429:
        return (
            f"Gateway rate limit or quota reached for '{AGENT_LABEL}'. {detail} "
            "Wait before retrying; do not loop."
        ).strip()
    if status == 400:
        return f"Gateway rejected the request as malformed or unsafe. {detail}".strip()
    if 500 <= status < 600:
        return f"Gateway or upstream error (HTTP {status}). {detail}".strip()
    return f"Unexpected gateway response HTTP {status}. {detail}".strip()


def _call(method: str, path: str, **kwargs: Any) -> Any:
    """Single choke point for outbound traffic: every request goes to the gateway."""
    headers = {"x-api-key": API_KEY, "Accept": "application/json"}
    headers.update(kwargs.pop("headers", None) or {})
    url = f"{BASE_URL}{path}"
    try:
        with httpx.Client(timeout=TIMEOUT) as client:
            response = client.request(method, url, headers=headers, **kwargs)
    except httpx.RequestError as exc:
        raise GatewayError(
            f"Could not reach the gateway at {BASE_URL}: {exc.__class__.__name__}. "
            "The tool call did not happen."
        ) from None

    if response.status_code >= 400:
        raise GatewayError(_explain(response))

    if not response.content:
        return {"ok": True, "status": response.status_code}
    try:
        return response.json()
    except ValueError:
        return {"ok": True, "status": response.status_code, "text": response.text[:2000]}


# --------------------------------------------------------------------- weather


@mcp.tool()
def get_weather(
    latitude: float,
    longitude: float,
    current: str = "temperature_2m,relative_humidity_2m,wind_speed_10m",
    hourly: str | None = None,
    forecast_days: int | None = None,
) -> dict:
    """Get a weather forecast for a coordinate.

    Args:
        latitude: Decimal degrees, -90 to 90.
        longitude: Decimal degrees, -180 to 180.
        current: Comma-separated current-condition variables (Open-Meteo names).
        hourly: Optional comma-separated hourly variables.
        forecast_days: Optional number of days, 1 to 16.
    """
    if not -90 <= latitude <= 90:
        raise GatewayError(f"latitude must be between -90 and 90, got {latitude}")
    if not -180 <= longitude <= 180:
        raise GatewayError(f"longitude must be between -180 and 180, got {longitude}")

    params: dict[str, Any] = {"latitude": latitude, "longitude": longitude}
    if current:
        params["current"] = current
    if hourly:
        params["hourly"] = hourly
    if forecast_days is not None:
        if not 1 <= forecast_days <= 16:
            raise GatewayError("forecast_days must be between 1 and 16")
        params["forecast_days"] = forecast_days
    return _call("GET", "/weather/v1/forecast", params=params)


# ---------------------------------------------------------------------- github
#
# repo is "owner/name". The gateway keeps its own allowlist and will refuse
# anything else with a 403, so the check here is only to produce a clearer
# message for an obviously malformed value -- it is not the security boundary.


def _split_repo(repo: str) -> tuple[str, str]:
    parts = repo.strip().strip("/").split("/")
    if len(parts) != 2 or not all(parts):
        raise GatewayError(
            f"repo must look like 'owner/name', got {repo!r}"
        )
    if any(c in p for p in parts for c in "?#&"):
        raise GatewayError(f"repo contains characters that are not allowed: {repo!r}")
    return parts[0], parts[1]


@mcp.tool()
def gh_list_issues(repo: str, state: str = "open", per_page: int = 30) -> list | dict:
    """List issues in a GitHub repository.

    The gateway holds the GitHub credential and will only use it against the one
    repository it is configured for; other repositories return a scope refusal.

    Args:
        repo: "owner/name" of the repository.
        state: "open", "closed", or "all".
        per_page: 1 to 100.
    """
    owner, name = _split_repo(repo)
    if state not in ("open", "closed", "all"):
        raise GatewayError("state must be one of: open, closed, all")
    if not 1 <= per_page <= 100:
        raise GatewayError("per_page must be between 1 and 100")
    return _call(
        "GET",
        f"/github/v1/repos/{owner}/{name}/issues",
        params={"state": state, "per_page": per_page},
    )


@mcp.tool()
def gh_create_issue(repo: str, title: str, body: str = "") -> dict:
    """Create an issue in a GitHub repository. Requires an operator identity.

    Only the title and body are sent. The gateway rebuilds the payload from an
    allowlist, so labels, assignees and milestones cannot be set through this
    tool -- an agent must not be able to notify or tag people.

    Args:
        repo: "owner/name" of the repository.
        title: Issue title, required and non-empty.
        body: Optional markdown body.
    """
    owner, name = _split_repo(repo)
    if not title.strip():
        raise GatewayError("title is required and cannot be blank")

    payload: dict[str, Any] = {"title": title}
    if body:
        payload["body"] = body
    return _call(
        "POST",
        f"/github/v1/repos/{owner}/{name}/issues",
        json=payload,
        headers={"Content-Type": "application/json"},
    )


# ----------------------------------------------------------------------- slack
#
# Slack has no "notifications" endpoint -- what a person means by "my Slack
# notifications" is recent activity in the channels they watch, which the Web
# API exposes as conversations.history. So that is what the reader gets.
#
# Channels are addressed by ID, not by name, and that is a deliberate cost. A
# name is nicer to type but anyone with the rope can rename a channel, and an
# allowlist a rename can silently redirect is not an allowlist. The gateway
# keeps the IDs; this process cannot resolve a name to one, and should not be
# able to -- resolving names would mean listing channels, which is a read the
# airlock does not grant.


def _check_channel(channel: str) -> str:
    """Shape check only. The gateway's allowlist is the security boundary."""
    c = channel.strip()
    if c.startswith("#"):
        raise GatewayError(
            f"Slack channels are addressed by ID here, not by name ({channel!r}). "
            "An ID looks like C09ABCDEF -- open the channel in Slack, choose "
            "'View channel details', and copy the ID at the bottom."
        )
    if not c:
        raise GatewayError("channel is required")
    return c


@mcp.tool()
def slack_read_messages(channel: str, limit: int = 20) -> dict:
    """Read recent messages from a Slack channel.

    This is what "check my Slack notifications" resolves to: the recent activity
    in one channel. The gateway holds the Slack credential and will only use it
    against the channels it is configured for; any other channel returns a scope
    refusal.

    Args:
        channel: Slack channel ID, e.g. "C09ABCDEF". Not a "#name".
        limit: How many messages to fetch, 1 to 100.
    """
    c = _check_channel(channel)
    if not 1 <= limit <= 100:
        raise GatewayError("limit must be between 1 and 100")
    return _call(
        "GET",
        "/slack/v1/conversations.history",
        params={"channel": c, "limit": limit},
    )


@mcp.tool()
def slack_post_message(channel: str, text: str) -> dict:
    """Post a message to a Slack channel. Requires an operator identity.

    Only the channel and the text are sent. The gateway rebuilds the payload
    from an allowlist, so blocks, attachments and a custom username cannot be
    set through this tool, and Slack's mention markup in the text is defused --
    an agent must not be able to impersonate anyone or page a whole workspace.

    Args:
        channel: Slack channel ID, e.g. "C09ABCDEF". Not a "#name".
        text: The message. Plain text or Slack markdown.
    """
    c = _check_channel(channel)
    if not text.strip():
        raise GatewayError("text is required and cannot be blank")
    return _call(
        "POST",
        "/slack/v1/chat.postMessage",
        json={"channel": c, "text": text},
        headers={"Content-Type": "application/json"},
    )


@mcp.tool()
def whoami() -> dict:
    """Report which gateway and identity this server is configured with.

    Useful when several agent identities are registered at once and a refusal
    needs to be attributed. Never returns the key itself.
    """
    return {
        "gateway": BASE_URL,
        "identity": AGENT_LABEL,
        "api_key_present": bool(API_KEY),
        "tools": [
            "get_weather",
            "gh_list_issues",
            "gh_create_issue",
            "slack_read_messages",
            "slack_post_message",
            "whoami",
        ],
        "note": "All backend credentials live in the gateway, not in this process.",
    }


if __name__ == "__main__":
    mcp.run()
