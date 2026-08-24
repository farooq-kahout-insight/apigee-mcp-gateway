"""Run one turn of an ADK agent and print what it said.

    python tests/run_agent_turn.py airlock_reader "What is the weather in Lahore?"

This exists so the smoke suite can drive a real agent without embedding ADK's
async plumbing in shell. It is the integration half of M11: the unit tests prove
the agent refuses to start wrong, and this proves the two planes actually meet --
a model call and a tool call, both through the gateway, both on one consumer key.

Exit codes are how it talks to smoke.sh, which cannot tell an infrastructure
problem from a policy one by reading stderr:

    0   the agent answered; the answer is on stdout
    3   ADK or LiteLLM is not installed -- skip, do not fail
    4   the free model tier rate-limited or refused capacity -- skip loudly
    5   the agent would not start: a startup contract violation -- fail
    1   anything else -- fail

The distinction between 4 and 1 matters more than it looks. A suite that goes
red because somebody else was using a free model tier teaches an operator to
ignore it, and an ignored suite is worse than no suite.
"""

import asyncio
import importlib
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
AGENTS = os.path.join(os.path.dirname(HERE), "adk-agents")
sys.path.insert(0, AGENTS)

APP = "agent-airlock-smoke"
USER = "smoke"
TIMEOUT = float(os.environ.get("AGENT_TURN_TIMEOUT", "180"))

# What a busy free tier looks like on the way back through LiteLLM. The gateway's
# own quota rejection is deliberately not in here: being throttled by our own
# policy is a real answer about the system, not a bad day at the provider.
BUSY = ("ratelimiterror", "429", "rate limit", "no allowed providers",
        "temporarily rate-limited", "503", "overloaded", "capacity")


def fail(code, message):
    print(message, file=sys.stderr)
    raise SystemExit(code)


async def one_turn(agent, prompt):
    from google.adk.runners import InMemoryRunner
    from google.genai import types

    runner = InMemoryRunner(agent=agent, app_name=APP)
    session = await runner.session_service.create_session(app_name=APP, user_id=USER)
    message = types.Content(role="user", parts=[types.Part(text=prompt)])

    # Every text part of every event, not just the final one. A tool-using turn
    # can put its answer in the event before the terminal one, and an empty
    # answer is the thing this test is looking for -- so being generous about
    # where the text came from keeps a pass honest rather than making one easy.
    said = []
    async for event in runner.run_async(user_id=USER, session_id=session.id,
                                        new_message=message):
        content = getattr(event, "content", None)
        for part in getattr(content, "parts", None) or []:
            text = getattr(part, "text", None)
            if text:
                said.append(text)
    return "\n".join(said).strip()


def main():
    if len(sys.argv) < 3:
        fail(1, "usage: run_agent_turn.py <agent-package> <prompt>")
    package, prompt = sys.argv[1], sys.argv[2]

    # airlock_common first, and not for what it exports: importing it sets
    # LITELLM_MODE, without which the litellm import below loads this repo's
    # .env into the process and hands it the very credentials the agent is built
    # not to have. Probing for the stack before that turns a working run into a
    # startup refusal, and the refusal names the launcher rather than the cause.
    try:
        from airlock_common import ConfigError
    except ImportError as exc:
        fail(3, f"cannot import airlock_common: {exc}")

    try:
        import google.adk  # noqa: F401
        import litellm  # noqa: F401
    except ImportError as exc:
        fail(3, f"agent stack not installed: {exc}")

    try:
        module = importlib.import_module(f"{package}.agent")
    except ConfigError as exc:
        fail(5, str(exc))
    except ImportError as exc:
        fail(3, f"cannot import {package}: {exc}")

    try:
        answer = asyncio.run(asyncio.wait_for(
            one_turn(module.root_agent, prompt), timeout=TIMEOUT))
    except asyncio.TimeoutError:
        fail(1, f"the agent did not finish a turn in {TIMEOUT:.0f}s")
    except Exception as exc:  # noqa: BLE001 - the exit code is the whole point
        text = f"{type(exc).__name__}: {exc}"
        if any(needle in text.lower() for needle in BUSY):
            fail(4, text)
        fail(1, text)

    if not answer:
        fail(1, "the agent produced no text")
    print(answer)


if __name__ == "__main__":
    main()
