# Security notes

This is a read-only MVP, not a certified security product.

- Keep `/mcp` behind HTTPS and use a random token of at least 32 characters.
- Do not expose port 8787 directly to the Internet.
- `/public/mcp` is intentionally unauthenticated for clients such as the ChatGPT web UI that may not accept generic Bearer credentials in their custom MCP connection flow. It is disabled by default. Enable only for a controlled test or after placing it behind a proper identity/rate-limiting gateway.
- The included public per-IP and daily search limits are in-memory and reset on restart. They are not sufficient abuse prevention for a multi-user production service.
- DNS validation and pinned connections reduce SSRF risk, but a production deployment should still enforce outbound network controls at the infrastructure layer.
- Do not add destructive or write tools to the public endpoint.
- Treat retrieved website content as untrusted input. Apply prompt-injection defenses in the client agent.
- Keep API keys out of Git, logs, container images, and screenshots.
