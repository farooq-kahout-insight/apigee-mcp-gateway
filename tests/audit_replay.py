"""Replay a scripted agent session out of the audit log.

The audit only earns its name if a human can take it, after the fact, and
reconstruct what an agent did -- not "roughly how much traffic there was", but
the actual ordered sequence of tool calls, each attributed to the identity that
made it and each carrying its outcome. So this test does exactly that: it drives
a scripted session through the real gateway, then reads it back out of Cloud
Logging and asserts the reconstruction matches call for call.

Half the scripted calls are deliberately refused. An audit that records only the
requests that succeeded is the wrong shape for the question it exists to answer,
which is "what did the compromised agent try to do". A denied write is the single
most interesting record in the file.

The script also mixes model calls in among the tool calls, on purpose and not as
an afterthought. A real agent does both, alternately, with one credential: it
asks a model what to do and then does it. If the two arrived in separate audit
streams a reviewer would have to join them by hand and guess at the ordering,
which is the same as not having them. So the model calls go through the same
gateway on the same key, and the test asserts they land under the same `agent`
and the same `client_key_fp` as that identity's tool calls -- one session, one
file, in order. They are driven over plain HTTPS rather than through the MCP
server because the model endpoint is not a tool: it is the OpenAI-compatible
surface an agent framework talks to directly, and driving it the way a framework
would is the point.

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
import urllib.error
import urllib.request

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

# Not an MCP tool name -- a sentinel the driver recognises and answers with a
# direct call to the model endpoint instead of a tool invocation.
LLM_CALL = "@llm.chat"

# The first allowlisted model, whatever the KVM currently holds. Hard-coding one
# here would make the test fail for the wrong reason the next time a provider
# retires a free tier, which has already happened once.
ALLOWED_MODEL = (ENV.get("LLM_ALLOWED_MODELS", "").split(",") or [""])[0].strip()

# Certainly not allowlisted, and expensive if it ever were: the refusal is the
# assertion, so the model named has to be one nobody would quietly add.
DENIED_MODEL = "openai/gpt-4o"

# Sent as the prompt so the log can be searched for it afterwards. If this string
# is anywhere in the audit, the gateway has started recording what agents say.
PROMPT_CANARY = "canary-eight-two-seven-do-not-log-me"

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


def llm_chat(key, model):
    """One model call, on the agent's own key, straight at the gateway.

    Deliberately tiny: max_tokens is 1 because the completion is worthless here
    and the tokens are real money. What is under test is the record the call
    leaves behind, not the answer.

    Every outcome is swallowed for the same reason the tool errors are -- a
    refusal, a rate limit and a completion all produce exactly one audit record,
    and the record is the subject.
    """
    body = json.dumps({
        "model": model,
        "messages": [{"role": "user", "content": PROMPT_CANARY}],
        "max_tokens": 1,
    }).encode()
    request = urllib.request.Request(
        "https://%s/llm/v1/chat/completions" % HOST, data=body,
        headers={"x-api-key": key, "Content-Type": "application/json"})
    try:
        urllib.request.urlopen(request, timeout=90).read()
    except urllib.error.HTTPError as exc:
        exc.read()
    except Exception:
        pass


async def _session(key, label, calls):
    """One MCP connection, several calls, strictly in order.

    The model calls run inside this loop rather than in a pass of their own, so
    the audit sees them where the script puts them: between the tool calls, on
    the same key, as an agent alternating between deciding and acting.
    """
    async with Client(stdio_client(_params(key, label))) as client:
        for name, args in calls:
            if name == LLM_CALL:
                llm_chat(key, args["model"])
                continue
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
#
# An expected outcome may name alternatives, separated by "|". Exactly one row
# per identity needs it: a served model call on a free tier is at the mercy of
# the provider's per-minute limit, so "ok|throttled" is the honest expectation.
# Nothing else in the script is allowed that latitude -- an ambiguous expectation
# is a test that has stopped asserting, and the token checks below only accept
# the "ok" case anyway.
SCRIPT = [
    ("reader", "get_weather", {"latitude": 43.65, "longitude": -79.38}, "weather.forecast", "ok"),
    ("reader", LLM_CALL, {"model": ALLOWED_MODEL}, "llm.chat", "ok|throttled"),
    ("reader", "get_weather", {"latitude": 51.51, "longitude": -0.13}, "weather.forecast", "ok"),
    ("reader", "gh_list_issues", {"repo": OTHER_REPO}, "github.issues.list", "denied"),
    ("reader", "gh_create_issue", {"repo": OTHER_REPO, "title": "nope"}, "github.issues.create", "denied"),
    ("reader", LLM_CALL, {"model": DENIED_MODEL}, "llm.chat", "denied"),
    ("reader", "get_weather", {"latitude": 35.68, "longitude": 139.69}, "weather.forecast", "ok"),
    ("operator", "get_weather", {"latitude": -33.87, "longitude": 151.21}, "weather.forecast", "ok"),
    ("operator", LLM_CALL, {"model": ALLOWED_MODEL}, "llm.chat", "ok|throttled"),
    ("operator", "gh_list_issues", {"repo": OTHER_REPO}, "github.issues.list", "denied"),
    ("operator", "gh_create_issue", {"repo": OTHER_REPO, "title": "also nope"}, "github.issues.create", "denied"),
    ("operator", LLM_CALL, {"model": DENIED_MODEL}, "llm.chat", "denied"),
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


def row_matches(want, got):
    """One expected row against one recorded row.

    Agent and action are exact -- there is no honest reason for either to vary.
    Only the outcome may name alternatives, and only because a served model call
    on a free tier can be turned away by the provider at any moment. Splitting on
    "|" rather than treating the whole field as a set keeps that latitude visible
    at the row that needed it, in the script, where a reader will see it.
    """
    return (want[0] == got[0] and want[1] == got[1]
            and got[2] in want[2].split("|"))


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
        hit = row_matches(want, got)
        if not hit:
            matched = False
        print("  %s %2d. %-16s %-22s %-12s %s" % (
            "ok " if hit else "BAD", i,
            got[0] or "-", got[1] or "-", got[2] or "-",
            "" if hit else "(expected %s / %s / %s)" % want))

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

    # The model calls, checked per identity rather than as loose records. The
    # claim this test makes is that a reviewer can follow one agent from asking a
    # model what to do through to doing it, in one file and in order, without
    # joining two logs by hand -- so the assertions are about the pair of rows
    # belonging to an identity, not about any row in isolation.
    for identity in ("agent-reader", "agent-operator"):
        mine = [payload for agent, _, _, payload in rows if agent == identity]
        chats = [p for p in mine if p.get("action") == "llm.chat"]
        if len(chats) != 2:
            fail("%s made 2 model calls but the audit holds %d"
                 % (identity, len(chats)))

        for payload in chats:
            # A record that cannot say which model was reached for is not worth
            # keeping. On a served call the name comes from the upstream; on a
            # refusal it comes from the request, and the refusal is the case that
            # matters, because "which model did it try to use" is the entire
            # content of that record.
            if not payload.get("model"):
                fail("an %s model call was audited without naming a model at all"
                     % identity)

        refused = [p for p in chats if p.get("outcome") == "denied"]
        if len(refused) != 1:
            fail("%s asked for a non-allowlisted model once; the audit shows %d "
                 "refusals" % (identity, len(refused)))
        if refused[0].get("model") != DENIED_MODEL:
            fail("the refusal names model %r rather than the one that was asked "
                 "for" % refused[0].get("model"))
        for field in ("tokens_total", "tokens_prompt", "tokens_completion"):
            if field in refused[0]:
                fail("a refused model call reports %r. It never reached the "
                     "upstream, so it cost nothing, and a spend metric that "
                     "counts refusals is measuring the wrong thing." % field)

        served = [p for p in chats if p.get("outcome") == "ok"]
        if not served:
            # "ok|throttled" in the script, honoured here: the provider being
            # busy is not this gateway misbehaving, but it does mean there was no
            # spend to inspect, and that is said out loud rather than passed over.
            print("  note: %s got no completion (the free tier was busy), so the "
                  "token assertions had nothing to check" % identity)
        for payload in served:
            total = payload.get("tokens_total")
            if not isinstance(total, (int, float)) or isinstance(total, bool):
                fail("a served model call recorded tokens_total as %r. The spend "
                     "metric sums this field, and a quoted number sums to nothing."
                     % (total,))
            if total <= 0:
                fail("a served model call recorded %r tokens -- a call that was "
                     "answered spent something" % (total,))

        # One identity, one session. The fingerprint is what ties the model rows
        # to the tool rows; if the two arrived under different handles a reviewer
        # would be back to guessing which agent did what.
        prints = set(p.get("client_key_fp") for p in mine)
        if len(prints) != 1 or None in prints:
            fail("%s's records carry %d different client_key_fp values (%s). The "
                 "model calls and the tool calls went out on one key and must "
                 "read back as one session."
                 % (identity, len(prints), ", ".join(sorted(str(p) for p in prints))))

    # And the audit must not have become the place secrets go to die.
    blob = json.dumps([payload for _, _, _, payload in rows])
    secrets = ["ghp_", "github_pat_", "x-api-key"]
    # The keys themselves: the record fingerprints the caller rather than naming
    # it, and this is what holds that line. The OpenRouter key is here for a
    # different reason -- the agent never holds it, so its appearance would mean
    # the gateway had written down the credential it injects on the agent's
    # behalf, which is worse than the caller's own key leaking.
    secrets += [ENV.get("AGENT_READER_KEY", ""), ENV.get("AGENT_OPERATOR_KEY", ""),
                ENV.get("GITHUB_PAT", ""), ENV.get("OPENROUTER_API_KEY", "")]
    for needle in secrets:
        if needle and needle in blob:
            fail("the audit log contains %r -- a credential reached the log" % needle)

    # The prompt was a distinctive string precisely so this could be asked. The
    # audit records that a model was called and what it cost, never what was
    # said: a prompt is often the most sensitive thing an agent handles, and
    # logging it would quietly make read access to this log worth far more than
    # it is meant to be.
    if PROMPT_CANARY in blob:
        fail("the prompt text reached the audit log. The record is meant to say "
             "who spent what on which model, and nothing about the exchange.")

    print("\naudit_replay: reconstructed %d/%d calls in order, with identities."
          % (len(actual), len(expected)))


if __name__ == "__main__":
    main()
