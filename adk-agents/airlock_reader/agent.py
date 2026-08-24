"""The read-only agent.

Nothing here enforces read-only. The scope sentence in the instruction is a
courtesy to the model, not a control: what actually stops this agent creating a
GitHub issue is that AGENT_READER_KEY belongs to the `tools-readonly` API
Product, and the gateway refuses the call. Prompt the agent into trying it and
the refusal appears in the audit log with `agent-reader` on it -- which is the
demo worth watching.
"""

from airlock_common import READER_SCOPE, build_root_agent

root_agent = build_root_agent(
    label="agent-reader",
    key_var="AGENT_READER_KEY",
    scope=READER_SCOPE,
    name="airlock_reader",
)
