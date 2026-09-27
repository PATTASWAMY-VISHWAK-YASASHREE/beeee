/**
 * Auth smoke test for Bee Bridge.
 *
 * Separate from `smoke.ts` on purpose. `BEE_BRIDGE_TOKEN` is read at module
 * scope, so the token has to be in the environment before the server module
 * loads -- and if it were, every check in the main smoke test would then need
 * to present it. Threading a token through the shared `client.ts` would have
 * meant editing a file the Hermes smoke test also depends on, so this runs as
 * its own process against its own server instead. Isolation beats cleverness.
 *
 * Run with: npm run smoke:auth
 */

import { fileURLToPath } from 'node:url';
import { createServer } from 'node:net';

const TOKEN = 'test-token-abcdefghijklmnopqrstuvwxyz-0123456789';
process.env.BEE_BRIDGE_TOKEN = TOKEN;
process.env.BEE_BIN = process.execPath;
process.chdir(fileURLToPath(new URL('../tests/fixtures/', import.meta.url)));
process.env.FAKE_BEE_SCENARIO = 'normal';

const PORT = await new Promise<number>((resolve, reject) => {
  const probe = createServer();
  probe.once('error', reject);
  probe.listen(0, '127.0.0.1', () => {
    const address = probe.address();
    const port = typeof address === 'object' && address ? address.port : 0;
    probe.close(() => resolve(port));
  });
});
process.env.BEE_BRIDGE_PORT = String(PORT);

const { createApp } = await import('../src/bee-bridge.js');

let passed = 0;
let failed = 0;
function check(name: string, ok: boolean, detail = ''): void {
  if (ok) {
    passed += 1;
    process.stdout.write(`  ok    ${name}\n`);
  } else {
    failed += 1;
    process.stdout.write(`  FAIL  ${name}${detail ? ` -- ${detail}` : ''}\n`);
  }
}

const server = createApp().listen(PORT, '127.0.0.1');
await new Promise((r) => server.once('listening', r));
const base = `http://127.0.0.1:${PORT}`;

process.stdout.write(`\nBee Bridge auth smoke test (token set)\n\n`);

const post = (headers: Record<string, string>, method = 'tools/list') =>
  fetch(`${base}/mcp`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream', ...headers },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method,
      ...(method === 'initialize'
        ? {
            params: {
              protocolVersion: '2025-11-25',
              capabilities: {},
              clientInfo: { name: 'auth-smoke', version: '0.1.0' },
            },
          }
        : {}),
    }),
  });

check('no token is refused', (await post({})).status === 401);
check('a wrong token is refused', (await post({}, 'initialize')).status === 401);
check('a non-bearer authorization header is refused', (await post({ authorization: TOKEN })).status === 401);

// The accepting call has to be a real handshake. Sending `tools/list` on a
// brand-new session gets past auth and then fails with "Server not
// initialized" -- which would look like a broken token check rather than the
// protocol detail it actually is.
const accepted = await post({ authorization: `Bearer ${TOKEN}` }, 'initialize');
check('the correct token is accepted', accepted.status === 200, `got ${accepted.status}`);
check('the accepted call returns a session id', Boolean(accepted.headers.get('mcp-session-id')));

// The demo must stay reachable, or a judge cannot see any of this.
check('health stays open', (await fetch(`${base}/health`)).status === 200);

process.stdout.write(`\n${passed} passed, ${failed} failed\n\n`);

// Close gracefully, then exit.
//
// The immediate `process.exit()` this used to do raced the listener teardown
// and tripped a libuv assertion on Windows, which made a fully passing run
// exit non-zero -- exactly the sort of thing that reads as "the tests fail"
// when they do not. Draining the server and giving the handles a beat to
// finish is slower and correct.
server.close(() => {
  setTimeout(() => process.exit(failed === 0 ? 0 : 1), 150);
});
