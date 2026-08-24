"""The write-capable agent.

Same code as the reader, one variable different. Its key belongs to the
`tools-operator` product, so the gateway lets it create issues -- on exactly one
allowlisted repository, with a payload the gateway validates before the PAT is
ever attached, at a rate the gateway meters, and with every attempt written to
the audit log whether it succeeded or not.
"""

from airlock_common import OPERATOR_SCOPE, build_root_agent

root_agent = build_root_agent(
    label="agent-operator",
    key_var="AGENT_OPERATOR_KEY",
    scope=OPERATOR_SCOPE,
    name="airlock_operator",
)
