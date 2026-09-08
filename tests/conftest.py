"""Shared fixtures for the gateway test suite.

Traffic tests need a *fresh* credential: SpikeArrest and Quota counters are keyed
on client_id, so reusing the long-lived agent apps would both pollute their
budgets and make the tests non-repeatable. Each test that spends quota therefore
gets a throwaway app that is deleted on teardown.
"""
import json
import os
import subprocess
import uuid

import pytest
import requests

# ENV lives in envfile.py so that the standalone tests -- the ones with their own
# exit codes rather than pytest's -- can read the same configuration without
# importing pytest. Re-exported here because the pytest modules already say
# `from conftest import ENV`.
from envfile import ENV  # noqa: F401

CP = "https://apigee.googleapis.com/v1"


ORG = ENV.get("APIGEE_ORG")
BASE = "https://" + ENV.get("APIGEE_HOST", "")
# Read from config/apps.json rather than hardcoded here, so a deployer who
# points scripts/provision.sh at their own developer identity does not also
# have to find and edit this second, easy-to-miss copy of it -- a mismatch
# between the two makes every throwaway app in the traffic tests fail against
# a developer that provision.sh never created.
_APPS_JSON = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           "config", "apps.json")
DEV_EMAIL = json.load(open(_APPS_JSON))["developer"]["email"]


@pytest.fixture(scope="session")
def token():
    out = subprocess.run(
        ["gcloud", "auth", "print-access-token", "--project", ORG],
        capture_output=True, text=True,
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
