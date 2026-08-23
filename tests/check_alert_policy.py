"""Assert the alert policy actually watches what it claims to.

A policy that exists but groups on nothing, or thresholds on the wrong metric,
is worse than no policy: it looks like coverage. Reads `gcloud alpha monitoring
policies list --format json` on stdin.
"""

import json
import sys

POLICIES = json.load(sys.stdin)
policy = None
for candidate in POLICIES:
    if str(candidate.get("displayName", "")).startswith("Agent Airlock"):
        policy = candidate
        break

if policy is None:
    print("no Agent Airlock alert policy found")
    sys.exit(1)

if not policy.get("enabled", False):
    print("the alert policy exists but is disabled")
    sys.exit(1)

if not policy.get("notificationChannels"):
    print("the alert policy has no notification channel -- it would alert nobody")
    sys.exit(1)

conditions = policy.get("conditions") or []
if not conditions:
    print("the alert policy has no conditions")
    sys.exit(1)

threshold = conditions[0].get("conditionThreshold") or {}
if "airlock_github_writes" not in threshold.get("filter", ""):
    print("the condition does not watch the airlock_github_writes metric: %r"
          % threshold.get("filter"))
    sys.exit(1)

if float(threshold.get("thresholdValue") or 0) != 20:
    print("threshold is %r, expected 20 per hour" % threshold.get("thresholdValue"))
    sys.exit(1)

aggregations = threshold.get("aggregations") or [{}]
if aggregations[0].get("alignmentPeriod") != "3600s":
    print("the window is %r, not an hour" % aggregations[0].get("alignmentPeriod"))
    sys.exit(1)

# Per-agent grouping is what makes the alarm name a culprit instead of just
# saying that traffic went up.
if "metric.label.agent" not in (aggregations[0].get("groupByFields") or []):
    print("the condition does not group by agent, so one runaway agent would be "
          "diluted by the other's ordinary traffic")
    sys.exit(1)

print("alert policy ok: %s" % policy.get("displayName"))
