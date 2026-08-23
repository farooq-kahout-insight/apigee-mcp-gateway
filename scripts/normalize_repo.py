"""Reduce whatever a human supplied for GITHUB_ALLOWED_REPO to owner/repo.

The gateway holds one repository name in a KVM and compares it, literally, to
the two path segments it lifted out of the request. That makes the stored value
load-bearing in a way its format does not advertise: a value that is merely
*wrong* fails safe, because nothing matches it and every GitHub call is refused
-- but it fails safe silently, and the refusal it produces points at the
caller's credential rather than at the allowlist. Somebody then spends an
afternoon auditing API keys that were never broken.

So the shape is settled once, here, at the moment a human hands it over.

A github.com URL is reduced rather than refused, because pasting the browser
address bar is the obvious thing to do and it says unambiguously which
repository was meant. A URL that points deeper than the repository root is not
reduced -- /owner/repo/issues could be read as the issues of owner/repo or as a
repository named "issues", and guessing which is meant is not a thing an
allowlist should do. Anything else is refused outright: an allowlist that was
misunderstood is worth failing the run over, because the whole reason it exists
is to be the one thing between a privileged token and every other repository.
"""

import re
import sys

if len(sys.argv) != 2:
    sys.stderr.write("usage: normalize_repo.py <owner/repo | github.com URL>\n")
    sys.exit(2)

raw = sys.argv[1].strip()
value = re.sub(r"^(?:https?://)?(?:www\.)?github\.com/", "", raw)
value = re.sub(r"(?:\.git)?/*$", "", value.split("?")[0].split("#")[0])

if not re.match(r"^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$", value):
    sys.stderr.write("cannot read %r as a single repository\n" % raw)
    sys.exit(1)

sys.stdout.write(value)
