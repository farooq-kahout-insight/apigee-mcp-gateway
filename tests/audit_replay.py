"""Replay a scripted agent session out of the audit log.

The audit only earns its name if a human can take it, after the fact, and
reconstruct what an agent did -- not "roughly how much traffic there was", but
the actual ordered sequence of tool calls, each attributed to the identity that
made it and each carrying its outcome. So this test does exactly that: it drives
ten calls through the real MCP server, then reads them back out of Cloud Logging
and asserts the reconstruction matches call for call.

Half the scripted calls are deliberately refused. An audit that records only the
requests that succeeded is the wrong shape for the question it exists to answer,
which is "what did the compromised agent try to do". A denied write is the single
most interesting record in the file.

Run it directly -- it is not a pytest module, because it needs an ordered,
single-threaded session and its own exit code:

    uv run --directory mcp-server --with requests python ../tests/audit_replay.py

Assumption, stated because it is load-bearing: no other traffic reaches the
gateway while this runs. The reconstruction is a time-ordered read of every audit
record written after t0, so a concurrent caller would appear as an extra row.
That is reported as a failure rather than filtered out, because silently dropping
records is precisely the bug this test exists to catch.
"""

import asyncio
import json
import os
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from envfile import ENV  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER_DIR = os.path.join(ROOT, "mcp-server")
SERVER = os.path.join(SERVER_DIR, "server.py")

ORG = ENV.get("APIGEE_ORG", "")
HOST = ENV.get("APIGEE_HOST", "")
LOG_NAME = os.environ.get("AUDIT_LOG_NAME", "agent-airlock-audit")

# Deliberately not the allowlisted repository: every GitHub call below is meant
# to be refused, so the replay can run against a live gateway without creating
# anything on anyone's repo and without needing the PAT to be present at all.
OTHER_REPO = "octocat/Hello-World"

# Cloud Logging ingestion is asynchronous, and the gateway logs from
# PostClientFlow -- after the response is already back -- so the last record can
# legitimately land a few seconds after the last call returns.
INGEST_TIMEOUT_S = 180
INGEST_POLL_S = 10


def fail(msg):
    print("FAIL: " + msg)
    sys.exit(1)


def skip(msg):
    print("SKIP: " + msg)
    sys.exit(0)


try:
    from mcp import Client, StdioServerParameters
    from mcp.client.stdio import get_default_environment, stdio_client
except ImportError:
    skip("mcp client not installed; run this under `uv run --directory mcp-server`")


# ------------------------------------------------------------------ the session


def _params(key, label):
    env = get_default_environment()
    env.update({"APIGEE_HOST": HOST, "AGENT_API_KEY": key, "AGENT_LABEL": label})
    return StdioServerParameters(
        command=sys.executable, args=[SERVER], env=env, cwd=SERVER_DIR
    )


async def _session(key, label, calls):
    """One MCP connection, several tool calls, strictly in order."""
    async with Client(stdio_client(_params(key, label))) as client:
        for name, args in calls:
            try:
                await client.call_tool(name, args)
            except Exception:
                # A refusal surfaces as a tool error. Either way the gateway has
                # already logged it, which is the only thing under test here.
                pass


# The script. Each row is (identity, tool, arguments, expected action, expected
# outcome). The identity also names the Apigee app that VerifyAPIKey resolves the
# key to, which is the field the audit records as the agent -- so asserting it
# checks the whole chain from key to log line.
SCRIPT = [
    ("reader", "get_weather", {"latitude": 43.65, "longitude": -79.38}, "weather.forecast", "ok"),
    ("reader", "get_weather", {"latitude": 51.51, "longitude": -0.13}, "weather.forecast", "ok"),
    ("reader", "gh_list_issues", {"repo": OTHER_REPO}, "github.issues.list", "denied"),
    ("reader", "gh_create_issue", {"repo": OTHER_REPO, "title": "nope"}, "github.issues.create", "denied"),
    ("reader", "get_weather", {"latitude": 35.68, "longitude": 139.69}, "weather.forecast", "ok"),
    ("operator", "get_weather", {"latitude": -33.87, "longitude": 151.21}, "weather.forecast", "ok"),
    ("operator", "gh_list_issues", {"repo": OTHER_REPO}, "github.issues.list", "denied"),
    ("operator", "gh_create_issue", {"repo": OTHER_REPO, "title": "also nope"}, "github.issues.create", "denied"),
    ("operator", "get_weather", {"latitude": 48.86, "longitude": 2.35}, "weather.forecast", "ok"),
    ("operator", "get_weather", {"latitude": 55.75, "longitude": 37.62}, "weather.forecast", "ok"),
]


def drive():
    """Run the script in order, one identity at a time. Returns t0."""
    keys = {
        "reader": ENV.get("AGENT_READER_KEY", ""),
        "operator": ENV.get("AGENT_OPERATOR_KEY", ""),
    }
    missing = [name for name, value in keys.items() if not value]
    if missing:
        skip("no key for %s; run scripts/provision.sh" % ", ".join(missing))

    # A whole second of slack before the first call: Cloud Logging timestamps
    # come from the gateway, not from this process, and a tight t0 risks clock
    # skew hiding the first record.
    t0 = time.time() - 1.0

    for identity in ("reader", "operator"):
        calls = [(tool, args) for who, tool, args, _, _ in SCRIPT if who == identity]
        asyncio.run(_session(keys[identity], identity, calls))
    return t0


# ------------------------------------------------------------------- the replay


def read_audit(since_epoch):
    """Every audit record written after `since_epoch`, oldest first.

    Shelling out to gcloud rather than importing google-cloud-logging keeps this
    free of a dependency the rest of the repo does not have, and reuses the
    credentials the operator already holds for everything else.
    """
    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(since_epoch))
    query = 'logName="projects/%s/logs/%s" AND timestamp>="%s"' % (ORG, LOG_NAME, stamp)
    out = subprocess.run(
        ["gcloud", "logging", "read", query, "--project", ORG,
         "--order", "asc", "--limit", "200", "--format", "json"],
        capture_output=True, text=True, shell=True, timeout=180,
    )
    if out.returncode != 0:
        fail("gcloud logging read failed: " + (out.stderr or "").strip()[:400])
    try:
        return json.loads(out.stdout or "[]")
    except ValueError:
        fail("gcloud returned non-JSON: " + (out.stdout or "")[:200])


def reconstruct(entries):
    """Turn raw log entries into (agent, action, outcome, payload) rows.

    Reads the JSON payload rather than the labels. The labels exist so metrics
    and alerts can group cheaply; the payload is the record of record, and this
    should fail loudly if the record ever arrives as unparsed text.
    """
    rows = []
    for entry in entries:
        payload = entry.get("jsonPayload")
        if not payload:
            fail("an audit entry has no jsonPayload -- it was logged as text, so "
                 "it cannot be queried by field: %r" % (entry.get("textPayload"),))
        rows.append((payload.get("agent"), payload.get("action"),
                     payload.get("outcome"), payload))
    return rows


def main():
    if not ORG or not HOST:
        skip("APIGEE_ORG / APIGEE_HOST not configured")

    print("driving %d calls through the gateway..." % len(SCRIPT))
    t0 = drive()

    expected = [("agent-" + who, action, outcome)
                for who, _, _, action, outcome in SCRIPT]

    deadline = time.time() + INGEST_TIMEOUT_S
    rows = []
    while True:
        rows = reconstruct(read_audit(t0))
        if len(rows) >= len(expected) or time.time() > deadline:
            break
        print("  %d/%d records so far; waiting for ingestion..."
              % (len(rows), len(expected)))
        time.sleep(INGEST_POLL_S)

    if len(rows) < len(expected):
        fail("only %d of %d calls were audited after %ds. A missing record means "
             "an agent action happened that nobody can see."
             % (len(rows), len(expected), INGEST_TIMEOUT_S))
    if len(rows) > len(expected):
        fail("%d records for %d calls -- something else was talking to the gateway "
             "during the replay; rerun on a quiet gateway."
             % (len(rows), len(expected)))

    actual = [(agent, action, outcome) for agent, action, outcome, _ in rows]
    matched = True
    for i, (want, got) in enumerate(zip(expected, actual), 1):
        if want != got:
            matched = False
        print("  %s %2d. %-16s %-22s %-12s %s" % (
            "ok " if want == got else "BAD", i,
            got[0] or "-", got[1] or "-", got[2] or "-",
            "" if want == got else "(expected %s / %s / %s)" % want))

    if not matched:
        fail("the reconstructed session does not match what was actually called")

    # The refused write is the record a human would actually go looking for, so
    # assert it carries enough to act on rather than merely existing.
    denied_writes = [payload for _, action, outcome, payload in rows
                     if action == "github.issues.create" and outcome == "denied"]
    if len(denied_writes) != 2:
        fail("expected 2 denied issue creations, found %d" % len(denied_writes))
    for payload in denied_writes:
        for field in ("ts", "client_key_fp", "proxy", "verb", "path", "status"):
            if not payload.get(field):
                fail("a denied write is missing %r -- not enough to investigate with"
                     % field)
        if payload.get("status") != 403:
            fail("a denied write recorded status %r, not 403" % payload.get("status"))

    # And the audit must not have become the place secrets go to die.
    blob = json.dumps([payload for _, _, _, payload in rows])
    secrets = ["ghp_", "github_pat_", "x-api-key"]
    # The keys themselves: the record fingerprints the caller rather than naming
    # it, and this is what holds that line.
    secrets += [ENV.get("AGENT_READER_KEY", ""), ENV.get("AGENT_OPERATOR_KEY", ""),
                ENV.get("GITHUB_PAT", "")]
    for needle in secrets:
        if needle and needle in blob:
            fail("the audit log contains %r -- a credential reached the log" % needle)

    print("\naudit_replay: reconstructed %d/%d calls in order, with identities."
          % (len(actual), len(expected)))


if __name__ == "__main__":
    main()
