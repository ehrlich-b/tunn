// Exported-only Node publisher driven by the Go relay integration test.
import { createInterface } from 'node:readline';
import * as http from 'node:http';
import { publish, publishHandler } from '../dist/index.js';

const lines = createInterface({ input: process.stdin })[Symbol.asyncIterator]();
const { mode, ...options } = JSON.parse((await lines.next()).value);
const handler = async (req, res) => {
  const body = []; for await (const chunk of req) body.push(chunk);
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Set-Cookie', ['first=a,b=c', 'second=d']);
  res.setHeader('Trailer', 'X-Final');
  res.write(JSON.stringify({ method: req.method, path: req.url, auth: req.headers.authorization ?? '', tunnAuth: req.headers['tunn-authorization'] ?? '', body: Buffer.concat(body).toString() }));
  res.addTrailers({ 'X-Final': ['first', 'second'] }); res.end();
};
let origin;
if (mode === 'origin') {
  origin = http.createServer(handler);
  await new Promise(resolve => origin.listen(0, '127.0.0.1', resolve));
  options.origin = `http://127.0.0.1:${origin.address().port}`;
}
const tunnel = origin ? publish(options) : publishHandler(handler, options);
try {
  console.log(JSON.stringify({ ready: await tunnel.waitReady() }));
  await lines.next();
  await tunnel.close();
  if (origin) {
    const result = await fetch(options.origin); await result.text();
    if (result.status !== 200) throw new Error('origin closed');
  }
  console.log(JSON.stringify({ closed: true }));
} catch (error) {
  console.log(JSON.stringify({ error: error.code ?? 'consumer_failed' }));
  await tunnel.done;
} finally {
  if (origin) await new Promise(resolve => origin.close(resolve));
  await lines.return();
  process.stdin.destroy();
}
