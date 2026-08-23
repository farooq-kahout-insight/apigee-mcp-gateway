"""p95 latency per target, computed from the audit log.

This exists because Apigee's custom-report API has no percentile function. It
accepts sum, avg, min and max, and -- the part worth knowing -- it does not
validate metric names at all, so asking for "p95_total_response_time" produces a
report that is created successfully and then renders nothing. Rather than ship a
report that looks like it answers the question, the average and the max go in the
Apigee view (scripts/reports.sh) and the percentile is computed here, from the
per-request numbers the gateway already writes into every audit record.

Average latency hides the failure mode anyone cares about. A target that answers
in 40ms for nineteen calls and 9 seconds for the twentieth averages out to
something reassuring; the agent waiting on the twentieth call is the one who
notices. p95 is the smallest summary that shows it.

Two latencies per record, and the gap between them is the point:

    latency_ms         the whole request, as the agent experienced it
    target_latency_ms  time spent waiting on the upstream

latency_ms minus target_latency_ms is the gateway's own overhead -- every policy
in the chain, the key check, the KVM read, the redaction pass. That is the number
that moves when a policy is added, and the one to quote when someone asks what
the airlock costs.

    python tests/latency_p95.py            # the last 24 hours
    python tests/latency_p95.py --hours 1

Exits non-zero if the log has no usable timings at all, which means the audit is
recording requests without recording how long they took.
"""

import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from envfile import ENV  # noqa: E402

ORG = ENV.get("APIGEE_ORG", "")
LOG_NAME = os.environ.get("AUDIT_LOG_NAME", "agent-airlock-audit")


def percentile(values, fraction):
    """Nearest-rank percentile on a sorted list.

    Nearest-rank rather than an interpolating variant on purpose: every value it
    returns is a latency that actually happened, so a number in this table can be
    traced back to a specific record in the log. An interpolated 340.7ms cannot.
    """
    if not values:
        return None
    ordered = sorted(values)
    rank = int(-(-len(ordered) * fraction // 1))  # ceil, without importing math
    return ordered[min(max(rank, 1), len(ordered)) - 1]


def read_records(hours):
    query = 'logName="projects/%s/logs/%s"' % (ORG, LOG_NAME)
    out = subprocess.run(
        ["gcloud", "logging", "read", query, "--project", ORG,
         "--freshness", "%dh" % hours, "--limit", "2000",
         "--order", "desc", "--format", "json"],
        capture_output=True, text=True, shell=True, timeout=300,
    )
    if out.returncode != 0:
        print("FAIL: gcloud logging read: " + (out.stderr or "").strip()[:400])
        sys.exit(1)
    entries = json.loads(out.stdout or "[]")
    return [e["jsonPayload"] for e in entries if e.get("jsonPayload")]


def group(records, key):
    buckets = {}
    for record in records:
        name = record.get(key) or "(none)"
        buckets.setdefault(name, []).append(record)
    return buckets


def table(title, buckets, field):
    print("\n%s" % title)
    print("  %-28s %6s %8s %8s %8s %8s" % ("", "n", "min", "avg", "p95", "max"))
    rows = 0
    for name in sorted(buckets):
        values = [r[field] for r in buckets[name]
                  if isinstance(r.get(field), (int, float))]
        if not values:
            # Shown rather than skipped, but the two cases read differently: a
            # named target with traffic and no timings is a broken record,
            # whereas the unnamed bucket is just the refusals -- a call stopped
            # at the gateway never reached an upstream to be timed.
            print("  %-28s %6d %s" % (
                name[:28], len(buckets[name]),
                "refused at the gateway, no upstream call" if name == "(none)"
                else "TIMINGS MISSING"))
            continue
        rows += 1
        print("  %-28s %6d %7dms %7dms %7dms %7dms" % (
            name[:28], len(values), min(values),
            sum(values) // len(values), percentile(values, 0.95), max(values)))
    return rows


def main():
    hours = 24
    if "--hours" in sys.argv:
        hours = int(sys.argv[sys.argv.index("--hours") + 1])
    if not ORG:
        print("SKIP: APIGEE_ORG not configured")
        sys.exit(0)

    records = read_records(hours)
    if not records:
        print("SKIP: no audit records in the last %dh; drive some traffic first" % hours)
        sys.exit(0)

    print("%d audit records over the last %dh" % (len(records), hours))

    timed = table("upstream latency per target (target_latency_ms)",
                  group(records, "target_host"), "target_latency_ms")
    table("end-to-end latency per proxy (latency_ms)",
          group(records, "proxy"), "latency_ms")

    # The overhead line. Only records that have both numbers can contribute, and
    # a refusal has no upstream call at all, so this is deliberately a smaller
    # population than the tables above.
    overheads = [r["latency_ms"] - r["target_latency_ms"] for r in records
                 if isinstance(r.get("latency_ms"), (int, float))
                 and isinstance(r.get("target_latency_ms"), (int, float))]
    if overheads:
        print("\ngateway overhead on served requests (latency minus upstream)")
        print("  %-28s %6d %7dms %7dms %7dms %7dms" % (
            "all policies", len(overheads), min(overheads),
            sum(overheads) // len(overheads),
            percentile(overheads, 0.95), max(overheads)))

    if not timed:
        print("\nFAIL: not one record carries target_latency_ms. The audit is "
              "recording that requests happened without recording how long they "
              "took, so no latency view can be built from it.")
        sys.exit(1)


if __name__ == "__main__":
    main()
