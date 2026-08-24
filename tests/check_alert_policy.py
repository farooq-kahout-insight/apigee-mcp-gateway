"""Assert an alert policy actually watches what it claims to.

A policy that exists but groups on nothing, or thresholds on the wrong metric,
is worse than no policy: it looks like coverage. Reads `gcloud alpha monitoring
policies list --format json` on stdin.

Usage: check_alert_policy.py [metric] [threshold]   (default: the github alarm)

The policy is found by the metric its condition watches, not by its display
name. There is more than one Agent Airlock alarm now, and name-prefix matching
picked whichever the API happened to return first -- so the github assertions
ran against the llm policy and reported a filter mismatch that was really a
selection bug. The metric is what the alarm is *about*, and it is also the one
part of a policy that cannot be edited in the console without changing which
question is being asked.

Two condition dialects are understood, because the two alarms are forced into
different ones. The github alarm counts entries, so a threshold condition says
what it means. The llm alarm sums a distribution -- the only metric shape Cloud
Logging will extract a value into -- and Monitoring will not compare a
distribution to a number, so that condition is written in MQL. The assertions
below are the same four either way: the right metric, the right number, an hour
of window, and a per-agent grouping.
"""

import json
import re
import sys

METRIC = sys.argv[1] if len(sys.argv) > 1 else "airlock_github_writes"
THRESHOLD = float(sys.argv[2]) if len(sys.argv) > 2 else 20.0

POLICIES = json.load(sys.stdin)


def watches(candidate):
    """Return ('threshold'|'mql', condition-body) for the condition on METRIC."""
    for condition in candidate.get("conditions") or []:
        threshold = condition.get("conditionThreshold") or {}
        if METRIC in (threshold.get("filter") or ""):
            return ("threshold", threshold)
        mql = condition.get("conditionMonitoringQueryLanguage") or {}
        if METRIC in (mql.get("query") or ""):
            return ("mql", mql)
    return None


policy = None
found = None
for candidate in POLICIES:
    found = watches(candidate)
    if found is not None:
        policy = candidate
        break

if policy is None:
    print("no alert policy watches the %s metric" % METRIC)
    sys.exit(1)

if not policy.get("enabled", False):
    print("the %s policy exists but is disabled" % METRIC)
    sys.exit(1)

if not policy.get("notificationChannels"):
    print("the %s policy has no notification channel -- it would alert nobody"
          % METRIC)
    sys.exit(1)

kind, condition = found

if kind == "threshold":
    if float(condition.get("thresholdValue") or 0) != THRESHOLD:
        print("threshold is %r, expected %r per hour"
              % (condition.get("thresholdValue"), THRESHOLD))
        sys.exit(1)

    aggregations = condition.get("aggregations") or [{}]
    if aggregations[0].get("alignmentPeriod") != "3600s":
        print("the window is %r, not an hour"
              % aggregations[0].get("alignmentPeriod"))
        sys.exit(1)

    # Per-agent grouping is what makes the alarm name a culprit instead of just
    # saying that traffic went up.
    if "metric.label.agent" not in (aggregations[0].get("groupByFields") or []):
        print("the condition does not group by agent, so one runaway agent would "
              "be diluted by the other's ordinary traffic")
        sys.exit(1)
else:
    query = condition.get("query") or ""
    # The same three assertions, read out of the query text. Read rather than
    # trusted: an MQL condition is one string, so a policy that has quietly lost
    # its grouping or its window looks identical from the outside to one that
    # has not.
    number = re.search(r"condition\s+\w+\s*>\s*([0-9.]+)", query)
    if not number or float(number.group(1)) != THRESHOLD:
        print("the MQL condition thresholds at %s, expected %r per hour"
              % (number.group(1) if number else "nothing recognisable", THRESHOLD))
        sys.exit(1)

    # An hour of history, however it is spelled -- delta(1h) buckets the clock,
    # `window 1h` slides. Either is an hour; a query with neither is not.
    if not re.search(r"(delta\(1h\)|window\s+1h|sliding\(1h\))", query):
        print("the MQL condition names no 1h window, so it is not measuring an "
              "hour of spend")
        sys.exit(1)

    if not re.search(r"group_by\s*\[\s*agent\b", query):
        print("the MQL condition does not group by agent, so one runaway agent "
              "would be diluted by the other's ordinary traffic")
        sys.exit(1)

    # And the sum specifically. A percentile or a mean over this metric reads as
    # a plausible alarm and answers a different question -- how big a typical
    # call was, not how much was spent -- which is the trap this condition is
    # written in MQL to avoid in the first place.
    if not re.search(r"sum\(value\.", query):
        print("the MQL condition does not sum the distribution's values, so it "
              "is alerting on the size of a typical call rather than on spend")
        sys.exit(1)

print("alert policy ok: %s" % policy.get("displayName"))
