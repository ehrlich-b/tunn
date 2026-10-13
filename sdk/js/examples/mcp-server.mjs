// v1 MCP SDK example. An independent MCP client can send an endpoint token
// in Tunn-Authorization; this app implements a stateless JSON HTTP transport.
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { publishHandler } from '@tunn/sdk';
import { pathToFileURL } from 'node:url';

export function mcpHandler(publicOrigin) {
  const expected = new URL(publicOrigin);
  return async (req, res) => {
    if (req.headers.host !== expected.host || (req.headers.origin && req.headers.origin !== expected.origin)) {
      res.writeHead(403).end(); return;
    }
    if (req.url !== '/mcp') { res.writeHead(404).end(); return; }
    if (req.method !== 'POST') { res.writeHead(405, { Allow: 'POST' }).end(); return; }
    const server = new McpServer({ name: 'tunn-node-example', version: '1.0.0' });
    server.registerTool('hello', { description: 'Return a greeting', inputSchema: {} }, async () => ({ content: [{ type: 'text', text: 'Hello from Node through tunn' }] }));
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
    const close = () => { void transport.close(); void server.close(); };
    res.once('close', close);
    try {
      const chunks = []; let bytes = 0;
      for await (const chunk of req) {
        bytes += chunk.length;
        if (bytes > 64 * 1024) { res.writeHead(413).end(); return; }
        chunks.push(chunk);
      }
      let body;
      try { body = JSON.parse(Buffer.concat(chunks).toString()); }
      catch { res.writeHead(400).end(); return; }
      await server.connect(transport);
      await transport.handleRequest(req, res, body);
    } catch {
      if (!res.headersSent) res.writeHead(500).end(); else res.destroy();
    }
  };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const name = process.env.TUNN_NAME;
  const publicOrigin = process.env.TUNN_PUBLIC_ORIGIN;
  if (!name || !publicOrigin || !process.env.TUNN_AUTH_TOKEN || !process.env.TUNN_TUNNEL_KEY || !process.env.TUNN_ENDPOINT_TOKEN) {
    throw new Error('Configure TUNN_NAME, TUNN_PUBLIC_ORIGIN and existing publisher/endpoint credentials');
  }
  const lifetime = new AbortController();
  process.once('SIGINT', () => lifetime.abort()); process.once('SIGTERM', () => lifetime.abort());
  const tunnel = publishHandler(mcpHandler(publicOrigin), {
    name,
    credentials: { authToken: process.env.TUNN_AUTH_TOKEN, tunnelKey: process.env.TUNN_TUNNEL_KEY, endpointToken: process.env.TUNN_ENDPOINT_TOKEN },
    signal: lifetime.signal,
  });
  try {
    const url = await tunnel.waitReady();
    if (new URL(url).origin !== new URL(publicOrigin).origin) throw new Error('Configured public origin differs from relay URL');
    console.log(`${url}/mcp`); await tunnel.wait();
  } catch (error) {
    if (error.code !== 'canceled') { console.error(error.code ?? 'example_failed'); process.exitCode = 1; }
  } finally { await tunnel.close().catch(() => {}); }
}
