"""Gateway acceptance tests. Run a subset with, e.g., pytest -k traffic."""
import time
from concurrent.futures import ThreadPoolExecutor

import pytest
import requests

from conftest import BASE

FORECAST = BASE + "/weather/v1/forecast?latitude=43.7&longitude=-79.4&current=temperature_2m"


def _json(resp):
    try:
        return resp.json()
    except ValueError:
        return {}


# --------------------------------------------------------------- traffic
@pytest.mark.traffic
def test_traffic_spike_arrest_returns_sanitized_429(throwaway_app):
    """A burst far above the 10ps ceiling is shed, with the gateway's own error shape."""
    key = throwaway_app("tools-readonly")
    hdrs = {"x-api-key": key}

    with ThreadPoolExecutor(max_workers=50) as pool:
        responses = list(pool.map(
            lambda _: requests.get(FORECAST, headers=hdrs, timeout=30), range(50)))

    codes = [r.status_code for r in responses]
    throttled = [r for r in responses if r.status_code == 429]
    assert throttled, f"expected some 429s from a 50-request burst, got {sorted(set(codes))}"

    body = _json(throttled[0])
    assert body.get("error") == "rate_limited", body
    # No Apigee internals may reach the caller.
    assert set(body) == {"error", "message"}, body
    text = throttled[0].text.lower()
    for leak in ("apigee", "policy", "spikearrest", "stacktrace", "steps."):
        assert leak not in text, f"fault body leaks '{leak}': {throttled[0].text}"


@pytest.mark.traffic
def test_traffic_quota_enforced_at_product_limit(throwaway_app):
    """Quota is read off the API Product, not hardcoded in the proxy.

    tools-quotaprobe declares 10/hour while the proxy's fallback is 100, so the
    cutoff landing on 10 proves the product is what governs. Spec M3 words this
    as "101st request on a 100/hour app"; a fresh app plus a deliberately
    different product limit tests the same enforcement in a tenth of the calls
    and stays repeatable.
    """
    limit = 10
    key = throwaway_app("tools-quotaprobe")
    hdrs = {"x-api-key": key}

    allowed = 0
    quota_body = None
    for _ in range(limit * 3):
        r = requests.get(FORECAST, headers=hdrs, timeout=30)
        body = _json(r)
        if r.status_code == 429 and body.get("error") == "rate_limited":
            time.sleep(1.0)  # SpikeArrest, not Quota -- back off and retry
            continue
        if r.status_code == 429 and body.get("error") == "quota_exceeded":
            quota_body = body
            break
        assert r.status_code == 200, f"unexpected {r.status_code}: {r.text[:200]}"
        allowed += 1
        time.sleep(0.25)  # stay under the 10ps spike ceiling

    assert quota_body is not None, f"quota never tripped after {allowed} allowed requests"
    assert allowed == limit, f"product declares {limit}/hour but {allowed} requests were allowed"
    assert set(quota_body) == {"error", "message"}, quota_body
