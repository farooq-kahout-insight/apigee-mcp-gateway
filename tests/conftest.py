"""Shared fixtures for the gateway test suite.

Traffic tests need a *fresh* credential: SpikeArrest and Quota counters are keyed
on client_id, so reusing the long-lived agent apps would both pollute their
budgets and make the tests non-repeatable. Each test that spends quota therefore
gets a throwaway app that is deleted on teardown.
"""
import os
import subprocess
import uuid

import pytest
import requests

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CP = "https://apigee.googleapis.com/v1"


def _load_env():
    env = {}
    for name in (".env", ".env.example"):
        path = os.path.join(ROOT, name)
        if not os.path.exists(path):
            continue
        for line in open(path, encoding="utf-8"):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                env.setdefault(k.strip(), v.strip())
    env.update({k: v for k, v in os.environ.items() if k.startswith("APIGEE_") or k.startswith("AGENT_")})
    return env


ENV = _load_env()
ORG = ENV.get("APIGEE_ORG")
BASE = "https://" + ENV.get("APIGEE_HOST", "")
DEV_EMAIL = "agents@agent-airlock.example.com"


@pytest.fixture(scope="session")
def token():
    out = subprocess.run(
        ["gcloud", "auth", "print-access-token", "--project", ORG],
        capture_output=True, text=True, shell=True,
    )
    tok = out.stdout.strip()
    if not tok:
        pytest.skip("no gcloud access token available")
    return tok


@pytest.fixture
def throwaway_app(token):
    """Factory: throwaway_app(product) -> consumer key. Deleted after the test."""
    created = []
    hdrs = {"Authorization": "Bearer " + token, "Content-Type": "application/json"}
    base = f"{CP}/organizations/{ORG}/developers/{DEV_EMAIL}/apps"

    def make(product):
        name = f"probe-{uuid.uuid4().hex[:12]}"
        r = requests.post(base, headers=hdrs, json={"name": name, "apiProducts": [product]}, timeout=30)
        r.raise_for_status()
        created.append(name)
        return r.json()["credentials"][0]["consumerKey"]

    yield make

    for name in created:
        requests.delete(f"{base}/{name}", headers=hdrs, timeout=30)
