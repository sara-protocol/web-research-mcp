const base = (process.env.MCP_BASE_URL || 'http://127.0.0.1:8787').replace(/\/$/, '');
const token = process.env.MCP_BEARER_TOKEN || '';

const health = await fetch(`${base}/healthz`);
if (!health.ok) throw new Error(`Health check failed: HTTP ${health.status}`);
const healthJson = await health.json();
console.log('PASS /healthz', healthJson);

const denied = await fetch(`${base}/mcp`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'initialize', params: { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 'smoke-test', version: '0.1.0' } } }) });
if (denied.status !== 401) throw new Error(`Expected unauthorized /mcp request to return 401, got ${denied.status}`);
console.log('PASS protected /mcp rejects missing token');

if (token) {
  const initialized = await fetch(`${base}/mcp`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: `Bearer ${token}`, accept: 'application/json, text/event-stream' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 2, method: 'initialize', params: { protocolVersion: '2025-03-26', capabilities: {}, clientInfo: { name: 'smoke-test', version: '0.1.0' } } })
  });
  if (!initialized.ok) throw new Error(`Authenticated MCP initialize failed: HTTP ${initialized.status}: ${await initialized.text()}`);
  console.log('PASS authenticated MCP initialize');
} else {
  console.log('SKIP authenticated initialize (set MCP_BEARER_TOKEN to test it)');
}
