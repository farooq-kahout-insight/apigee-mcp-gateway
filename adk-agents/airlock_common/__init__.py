"""Shared factory for the Airlock ADK agents.

Kept as a sibling package of the agent packages rather than inside one of them:
ADK puts the parent directory of the agent it is running on sys.path, so
``adk run adk-agents/airlock_reader`` can import this, and neither agent has to
reach into the other.
"""

from .factory import (  # noqa: F401
    ConfigError,
    FORBIDDEN_ENV,
    OPERATOR_SCOPE,
    READER_SCOPE,
    Settings,
    build_root_agent,
    mcp_child_env,
    mcp_command,
    settings,
)
