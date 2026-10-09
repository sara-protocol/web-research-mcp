// Example: call this remote MCP server through the OpenAI Responses API.
// Requires OPENAI_API_KEY, MCP_SERVER_URL, and MCP_BEARER_TOKEN.
import OpenAI from 'openai';

const client = new OpenAI();
const serverUrl = process.env.MCP_SERVER_URL;
const token = process.env.MCP_BEARER_TOKEN;
if (!serverUrl || !token) throw new Error('Set MCP_SERVER_URL and MCP_BEARER_TOKEN.');

const response = await client.responses.create({
  model: process.env.OPENAI_MODEL || 'gpt-5.4',
  tools: [{
    type: 'mcp',
    server_label: 'web_research',
    server_description: 'Read-only web search and public webpage extraction.',
    server_url: serverUrl,
    authorization: `Bearer ${token}`,
    require_approval: 'always'
  }],
  input: 'Use web_search to find three authoritative sources about MCP Streamable HTTP. Return the source URLs and summarize the common points.'
});

console.log(response.output_text);
