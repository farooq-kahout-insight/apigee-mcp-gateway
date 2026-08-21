# agent-airlock MCP server

Stdio MCP server exposing `get_weather`, `gh_list_issues`, `gh_create_issue` and
`whoami`. It talks to nothing except the Apigee gateway.

Run it with `uv`, which resolves dependencies from `pyproject.toml` on the fly:

```
uv run --directory mcp-server server.py
```

See the repository README for the Claude Code registration JSON.
