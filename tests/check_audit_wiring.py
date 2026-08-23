"""Assert the audit is wired into the flows that can actually run it.

This exists because of a specific, expensive bug. PostClientFlow is the obvious
home for an audit -- it runs after the response has gone out, so logging there
costs the caller nothing and cannot be skipped by an early exit -- but Apigee
runs *only* MessageLogging policies in it. A JavaScript step placed there is
reported in a debug trace as executing successfully, with a result of true and
an execution time of zero, and sets no variables at all. The gateway logged
perfectly formed, entirely empty records, and Cloud Logging quietly dropped
them.

So the shape is load-bearing: the record is assembled on the response path and
on the fault path, where JavaScript really runs, and only the write happens in
PostClientFlow. This checks that shape rather than trusting a comment to hold
it in place.

Exits non-zero with an explanation. Driven by scripts/smoke.sh.
"""

import io
import os
import sys
import xml.etree.ElementTree as ET

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROXIES = ("weather-v1", "github-v1")

problems = []


def steps(element):
    """Policy names of the <Step> children under an element, in order."""
    if element is None:
        return []
    return [name.text.strip() for name in element.iterfind(".//Step/Name")
            if name.text]


for proxy in PROXIES:
    path = os.path.join(ROOT, "proxies", proxy, "apiproxy", "proxies", "default.xml")
    tree = ET.parse(path)
    root = tree.getroot()
    where = proxy + " default.xml"

    post_client = steps(root.find("./PostClientFlow"))
    if post_client != ["FC-Audit-Log"]:
        problems.append("%s: PostClientFlow should hold exactly the audit write, "
                        "found %s" % (where, post_client or "nothing"))

    post_flow = steps(root.find("./PostFlow/Response"))
    if "FC-Audit-Build" not in post_flow:
        problems.append("%s: PostFlow/Response does not build the audit record; "
                        "successful calls would be logged empty" % where)
    elif post_flow.index("FC-Audit-Build") < post_flow.index("FC-Outbound-Redaction"):
        problems.append("%s: the audit record is built before redaction, so it "
                        "could describe a body the caller never saw" % where)

    # Both fault paths, because a refusal never reaches PostFlow -- and a
    # refusal is the record a human most wants to find later.
    for rule, label in ((root.find("./FaultRules/FaultRule"), "FaultRule"),
                        (root.find("./DefaultFaultRule"), "DefaultFaultRule")):
        if "FC-Audit-Build" not in steps(rule):
            problems.append("%s: %s does not build the audit record; refused "
                            "calls would go unlogged" % (where, label))


# And the flows themselves: whatever PostClientFlow reaches must be a policy
# type that flow will actually execute.
log_dir = os.path.join(ROOT, "sharedflows", "sf-audit-log", "sharedflowbundle")
for name in steps(ET.parse(os.path.join(log_dir, "sharedflows", "default.xml")).getroot()):
    policy = os.path.join(log_dir, "policies", name + ".xml")
    if not os.path.exists(policy):
        problems.append("sf-audit-log references a missing policy %s" % name)
        continue
    kind = ET.parse(policy).getroot().tag
    if kind != "MessageLogging":
        problems.append("sf-audit-log runs a %s policy (%s), which PostClientFlow "
                        "will silently skip" % (kind, name))

# Labels on the CloudLogging policy are a trap: Apigee does not expand message
# templates inside a label value, so a <Label> whose value is {some.variable}
# arrives in every entry as that literal text. It reads like working metadata
# right up until a log metric is filtered on it and matches everything or
# nothing. The record is a JSON payload and metrics can filter on jsonPayload,
# so the labels are not needed; this keeps them from coming back.
ml = os.path.join(log_dir, "policies", "ML-Cloud-Logging.xml")
if os.path.exists(ml):
    root = ET.parse(ml).getroot()
    for labels in root.iter("Labels"):
        for value in labels.iter("Value"):
            text = (value.text or "").strip()
            if text.startswith("{") and text.endswith("}"):
                problems.append(
                    "ML-Cloud-Logging has a label whose value is the template %s; "
                    "Apigee will log it literally, not expand it" % text)

build_dir = os.path.join(ROOT, "sharedflows", "sf-audit-build", "sharedflowbundle")
build_steps = steps(ET.parse(os.path.join(build_dir, "sharedflows", "default.xml")).getroot())
if "JS-Build-Audit-Record" not in build_steps:
    problems.append("sf-audit-build no longer builds the record")
elif build_steps[-1] != "JS-Build-Audit-Record":
    # Everything else in this flow exists to put a variable within the builder's
    # reach -- the app-name lookup that repairs attribution on a product-scope
    # refusal, and whatever follows it. A step that ran after the record was
    # assembled would be gathering evidence for a record that no longer accepts it.
    problems.append("sf-audit-build assembles the record before %s has run"
                    % build_steps[build_steps.index("JS-Build-Audit-Record") + 1])

# Any AccessEntity policy hands the whole entity to the flow, credentials and
# all: the app entity carries every consumer secret the app holds, in plaintext,
# in a variable named after the policy. Apigee's default trace masking covers
# client_id and access_token and knows nothing about it, so the mask has to be
# declared, and the place it is declared is provision.sh. Checked here rather
# than trusted, because the policy is the easy half -- someone adding a second
# AccessEntity next year gets the same exposure for free and no reminder.
provision = io.open(os.path.join(ROOT, "scripts", "provision.sh"),
                    encoding="utf-8").read()
for directory in ("sf-audit-build",):
    policy_dir = os.path.join(ROOT, "sharedflows", directory, "sharedflowbundle", "policies")
    for filename in sorted(os.listdir(policy_dir)):
        root = ET.parse(os.path.join(policy_dir, filename)).getroot()
        if root.tag != "AccessEntity":
            continue
        variable = "AccessEntity." + root.get("name")
        if variable not in provision:
            problems.append(
                "%s puts the app's consumer secrets in %s, and provision.sh does "
                "not mask that variable -- anyone who can start a debug session "
                "can read them" % (filename, variable))

if problems:
    for line in problems:
        print(line)
    sys.exit(1)
print("audit wiring ok")
