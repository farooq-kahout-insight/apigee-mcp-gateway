"""The repository's configuration, as the tests see it.

Split out of conftest.py because two of the tests here are not pytest modules --
audit_replay.py and latency_p95.py run standalone, with their own exit codes, and
importing conftest dragged pytest into processes that have no use for it. That
broke the documented command for the replay outright.

Precedence, deliberately: .env first, .env.example only to fill gaps, and the
real environment last so a shell variable can override either. That ordering is
what lets `AGENT_READER_KEY=... python tests/...` work without editing a file.
"""

import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_env():
    env = {}
    for name in (".env", ".env.example"):
        path = os.path.join(ROOT, name)
        if not os.path.exists(path):
            continue
        for line in open(path, encoding="utf-8"):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, value = line.split("=", 1)
                env.setdefault(key.strip(), value.strip())
    env.update({k: v for k, v in os.environ.items()
                if k.startswith("APIGEE_") or k.startswith("AGENT_")})
    return env


ENV = load_env()
