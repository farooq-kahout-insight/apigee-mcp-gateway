"""Assertions over a window of audit records, read from `gcloud logging read`.

Usage: check_audit_entries.py <mode> < entries.json

Modes:
  served   a successful forecast is present, attributed to an agent identity
  refused  a call the product did not permit is present, recorded as denied
  named    a refusal at the product scope still says which agent was refused
  clean    no credential appears anywhere in the window
  caller   the recorded address is the caller's, not the load balancer's
  llm_spend   a served model call is present, with a real token count and no text
  llm_denied  a refused model call names both the agent and the model it wanted
  session_model <agent>  the named agent's model call is in the window
  session_tool  <agent>  its tool call is too, on the same credential

Kept as a separate script rather than inlined into smoke.sh because the shape of
a log entry is worth asserting field by field, and doing that in shell would be
a wall of grep that nobody could read a month later.
"""

import json
import os
import sys

MODE = sys.argv[1] if len(sys.argv) > 1 else ""
WHO = sys.argv[2] if len(sys.argv) > 2 else ""

try:
    ENTRIES = json.load(sys.stdin)
except ValueError:
    print("no JSON on stdin -- gcloud returned nothing")
    sys.exit(1)

RECORDS = []
for entry in ENTRIES:
    payload = entry.get("jsonPayload")
    if payload is None:
        print("an entry arrived as text, not JSON: %r" % entry.get("textPayload"))
        sys.exit(1)
    RECORDS.append(payload)

if not RECORDS:
    print("no audit records in the window at all")
    sys.exit(1)


def find(**want):
    return [r for r in RECORDS if all(r.get(k) == v for k, v in want.items())]


def fail(msg):
    print(msg)
    print("saw: " + ", ".join(
        "%s/%s/%s" % (r.get("agent"), r.get("action"), r.get("outcome"))
        for r in RECORDS[:8]))
    sys.exit(1)


# Two checks that apply whatever mode was asked for, because both failures are
# invisible in a passing run: an unexpanded template looks like data until
# someone filters on it, and a leaked key looks like an opaque identifier.

for record in RECORDS:
    for key, value in record.items():
        if isinstance(value, str) and value.startswith("{") and value.endswith("}"):
            print("field %r holds the literal template %r -- Apigee did not "
                  "expand it, so every record carries the same constant" % (key, value))
            sys.exit(1)

# The record is meant to fingerprint the caller's key, never to carry it. This
# is checked here rather than only under `clean` because a key in the log is a
# failure of the audit regardless of which assertion the caller asked for.
BLOB = json.dumps(RECORDS)
for name in ("AGENT_READER_KEY", "AGENT_OPERATOR_KEY", "GITHUB_PAT"):
    secret = os.environ.get(name, "")
    if secret and secret in BLOB:
        print("the audit contains $%s verbatim -- read access to the log is now "
              "equivalent to holding the credential" % name)
        sys.exit(1)
if any("client_id" in r for r in RECORDS):
    print("a record carries client_id; on Apigee that field is the consumer key "
          "itself, so it must be fingerprinted rather than logged")
    sys.exit(1)


if MODE == "served":
    hits = find(proxy="weather-v1", action="weather.forecast", outcome="ok")
    if not hits:
        fail("no successful forecast was audited")
    # The identity is the whole point: a record that cannot say who called is
    # not evidence of anything.
    named = [r for r in hits if r.get("agent") and r["agent"] != "unauthenticated"]
    if not named:
        fail("the forecast was audited without an agent identity")
    record = named[0]
    for field in ("ts", "client_key_fp", "proxy", "revision", "verb", "path",
                  "status", "latency_ms"):
        if record.get(field) in (None, ""):
            fail("an audited call is missing %r" % field)
    if record.get("status") != 200:
        fail("a successful forecast recorded status %r" % record.get("status"))

elif MODE == "refused":
    hits = [r for r in RECORDS if r.get("outcome") == "denied"]
    if not hits:
        fail("a refusal happened but nothing was audited as denied")
    record = hits[0]
    if record.get("status") != 403:
        fail("a denied call recorded status %r, not 403" % record.get("status"))
    for field in ("ts", "proxy", "verb", "path", "action"):
        if record.get(field) in (None, ""):
            fail("a denied call is missing %r -- too little to investigate with"
                 % field)

elif MODE == "named":
    # InvalidApiKeyForGivenResource is raised only when the key was found and the
    # product simply does not cover the resource -- so by the fault's own meaning a
    # registered app exists, and a record that says "unauthenticated" is stating
    # something the gateway knows to be false. It said exactly that for months:
    # Apigee raises the fault from inside VerifyAPIKey and publishes no identity,
    # so the two variables the builder read were both empty, and the one record an
    # investigation would reach for first -- a known agent reaching past its scope
    # -- was the one that named nobody. AE-Resolve-App looks the app up from the
    # key instead of waiting for VerifyAPIKey to volunteer it.
    scoped = [r for r in RECORDS
              if r.get("fault") == "InvalidApiKeyForGivenResource"]
    if not scoped:
        fail("no product-scope refusal in the window to check attribution against")
    for record in scoped:
        agent = record.get("agent")
        if not agent or agent == "unauthenticated":
            fail("a call refused at the product scope was audited as %r. The key "
                 "was recognised -- that is what the fault means -- so the agent "
                 "is knowable and the record is disclaiming knowledge it has"
                 % (agent or None,))


elif MODE == "caller":
    # Google's load balancers front the gateway out of 35.191.0.0/16 and
    # 130.211.0.0/22. Seeing one of those as client_ip does not mean the caller
    # is unknown -- it means the record captured the wrong end of the forwarding
    # chain, which is the specific regression this mode exists to catch. It was
    # live once: served requests all named a front end while refusals were
    # correct, because the two are built at different points in the flow.
    def is_google_frontend(ip):
        return ip.startswith("35.191.") or ip.startswith("130.211.")

    served = find(outcome="ok")
    if not served:
        fail("no served call in the window to check the caller address against")
    for record in served:
        ip = record.get("client_ip") or ""
        if not ip:
            fail("a served call was audited with no client_ip at all")
        if is_google_frontend(ip):
            fail("a served call records client_ip %r, which is a Google front "
                 "end rather than the caller -- the address is being read after "
                 "Apigee has rewritten X-Forwarded-For for its own upstream call"
                 % ip)

    # And the two paths must agree. They are assembled in different places, so
    # the only way to know the served path is right is to compare it with the
    # refusal path, which reads the header while it is still the client's.
    addresses = set()
    for record in RECORDS:
        ip = record.get("client_ip")
        if ip and not is_google_frontend(ip):
            addresses.add(ip)
    if len(addresses) > 1:
        fail("the window records %d different caller addresses (%s) for what "
             "should be one caller; the served and refused paths disagree"
             % (len(addresses), ", ".join(sorted(addresses))))

elif MODE == "llm_spend":
    hits = [r for r in RECORDS
            if r.get("action") == "llm.chat" and r.get("outcome") == "ok"]
    if not hits:
        fail("no served model call was audited")
    record = hits[0]
    if not record.get("agent") or record["agent"] == "unauthenticated":
        fail("a served model call was audited as %r. Spend that cannot be "
             "attributed cannot be budgeted." % (record.get("agent") or None,))
    if not record.get("model"):
        fail("a served model call was audited without naming the model")
    total = record.get("tokens_total")
    # A number, not a string. The log-based metric extracts this field and sums
    # it; a quoted value extracts as nothing and the spend graph stays flat
    # while the bill does not.
    if isinstance(total, bool) or not isinstance(total, (int, float)):
        fail("tokens_total was audited as %r rather than a number, so the spend "
             "metric would sum it to zero" % (total,))
    if total <= 0:
        fail("a served model call recorded %r tokens; an answered call spent "
             "something" % (total,))

    # And the property the whole schema is arranged around: the audit says who
    # spent what on which model, and nothing whatsoever about what was said.
    canary = os.environ.get("AIRLOCK_PROMPT_CANARY", "")
    if canary and canary in BLOB:
        fail("the prompt text reached the audit log. A prompt is often the most "
             "sensitive thing an agent handles; logging it makes read access to "
             "this log worth far more than it is meant to be.")
    for record in RECORDS:
        for field in ("messages", "prompt", "completion", "choices", "content"):
            if field in record:
                fail("an audit record carries %r -- the exchange itself is being "
                     "logged" % field)

elif MODE == "llm_denied":
    hits = [r for r in RECORDS
            if r.get("action") == "llm.chat" and r.get("outcome") == "denied"]
    if not hits:
        fail("a model request was refused but nothing was audited as denied")
    for record in hits:
        agent = record.get("agent")
        if not agent or agent == "unauthenticated":
            fail("a refused model call was audited as %r. The key was valid -- it "
                 "was the model that was not -- so the agent is knowable"
                 % (agent or None,))
        # The requested model, surviving a call that never reached the upstream.
        # Without it the record says only that somebody was refused something,
        # which is not a finding anyone can act on.
        if not record.get("model"):
            fail("a refused model call does not say which model was asked for")
        for field in ("tokens_total", "tokens_prompt", "tokens_completion"):
            if field in record:
                fail("a refused model call reports %r. It never reached the "
                     "upstream and cost nothing; a spend series that counts "
                     "refusals is measuring the wrong thing." % field)

elif MODE == "session_model":
    # An agent's turn, seen from the gateway. The assertion is attribution, not
    # spend -- llm_spend already covers the shape of the record. What is new here
    # is that a model call made by ADK, through LiteLLM, with a consumer key
    # standing in for a provider credential, arrives named.
    if not WHO:
        print("session_model needs an agent name")
        sys.exit(2)
    hits = [r for r in RECORDS
            if r.get("action") == "llm.chat" and r.get("agent") == WHO]
    if not hits:
        fail("no model call by %r in the window. The agent answered, so either it "
             "reached a model that is not this gateway, or the call was attributed "
             "to somebody else." % WHO)
    if not any(r.get("outcome") == "ok" for r in hits):
        fail("every model call by %r in the window was refused" % WHO)

elif MODE == "session_tool":
    # The claim this mode exists for is not "a tool ran". It is that the model
    # plane and the tool plane are one identity on one credential -- which is
    # what makes the reader agent's inability to write a property of the
    # gateway rather than a property of its prompt.
    if not WHO:
        print("session_tool needs an agent name")
        sys.exit(2)
    tools = [r for r in RECORDS
             if r.get("agent") == WHO and r.get("action")
             and r["action"] != "llm.chat" and r.get("outcome") == "ok"]
    if not tools:
        fail("no served tool call by %r in the window" % WHO)
    models = [r for r in RECORDS
              if r.get("action") == "llm.chat" and r.get("agent") == WHO]
    if not models:
        fail("a tool call by %r is audited but no model call is, so this window "
             "does not show one agent using both planes" % WHO)
    fingerprints = {r.get("client_key_fp") for r in tools + models}
    fingerprints.discard(None)
    if len(fingerprints) != 1:
        fail("the model calls and tool calls by %r were made with %d different "
             "credentials (%s). One agent, one key, one set of products is the "
             "whole basis for the permission story."
             % (WHO, len(fingerprints), ", ".join(sorted(map(str, fingerprints)))))

elif MODE == "clean":
    blob = BLOB
    needles = ["ghp_", "github_pat_", "x-api-key", "Bearer ", "Authorization"]
    for needle in needles:
        if needle in blob:
            print("the audit contains %r -- a credential reached the log" % needle)
            sys.exit(1)

else:
    print("unknown mode %r" % MODE)
    sys.exit(2)

print("%s: ok over %d records" % (MODE, len(RECORDS)))
