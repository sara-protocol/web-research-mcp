# Claude Code remote MCP connection

Set `WEB_MCP_TOKEN` in the shell environment to the same value as `MCP_BEARER_TOKEN` on the server.

```bash
claude mcp add --transport http --scope user \
  --header "Authorization: Bearer ${WEB_MCP_TOKEN}" \
  web-research https://YOUR_DOMAIN.example/mcp
```

Verify:

```bash
claude mcp list
```

In Claude Code, run `/mcp` and confirm `web-research` is connected. If your shell is PowerShell, set the variable first with `$env:WEB_MCP_TOKEN="your-token"` and then run the add command on one line.
