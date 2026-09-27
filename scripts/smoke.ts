/**
 * End-to-end smoke test for Bee Bridge.
 *
 * Starts the real server in-process, points it at the fake Bee CLI, and drives
 * it over the real wire protocol with the same raw JSON-RPC client the Hermes
 * smoke test uses. Nothing is mocked except Bee itself.
 *
 * The reason this exists separately from the unit tests: the failure modes that
 * actually bite an MCP server are protocol-level (session headers, the 404 on
 * an unknown session, DNS-rebinding) and nothing short of a real HTTP round
 * trip will surface them.
 *
 * Run with: npm run smoke
 */

import { fileURLToPath } from 'node:url';
import { createServer } from 'node:net';

// Must be set before the Bee modules load: BEE_BIN is read at module scope.
// `fileURLToPath` rather than `URL.pathname`, because the repo path contains
// spaces and parentheses, which `pathname` percent-encodes into a dead path.
const FIXTURES = fileURLToPath(new URL('../tests/fixtures/', import.meta.url));
process.env.BEE_BIN = process.execPath;
// `node mcp serve ...` resolves the leading `mcp` against the cwd; see the
// comment in tests/fixtures/mcp for why this indirection exists on Windows.
process.chdir(FIXTURES);
process.env.FAKE_BEE_SCENARIO = 'normal';

/**
 * Find a free port, then publish it as BEE_BRIDGE_PORT before the server module
 * loads.
 *
 * This indirection is not optional. The server builds its DNS-rebinding
 * allow-list from BEE_BRIDGE_PORT, and that protection is a spec MUST -- so
 * listening on some other port makes every MCP call fail with a 403, which is
 * the server working correctly. The probe-then-bind dance is how we test it
 * without hard-coding a port that may already be taken.
 */
function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const probe = createServer();
    probe.once('error', reject);
    probe.listen(0, '127.0.0.1', () => {
      const address = probe.address();
      const port = typeof address === 'object' && address ? address.port : 0;
      probe.close(() => resolve(port));
    });
  });
}

const PORT = await freePort();
process.env.BEE_BRIDGE_PORT = String(PORT);

const { createApp } = await import('../src/bee-bridge.js');
const { closeBeeClient } = await import('../src/bee/tools.js');
const { openSession, toolText } = await import('./client.js');

/**
 * Switch the fake Bee's behaviour.
 *
 * The scenario is read by the fixture process at startup, so changing the
 * variable alone does nothing: the already-spawned child keeps serving the
 * scenario it was launched with. Dropping the shared client forces the next
 * call to reconnect, which respawns the fixture with the new setting. Getting
 * this wrong is a silent false negative -- the test looks like it is checking
 * the injection path while quietly re-reading the benign fixture.
 */
async function scenario(name: string): Promise<void> {
  await closeBeeClient();
  process.env.FAKE_BEE_SCENARIO = name;
}

let passed = 0;
let failed = 0;

function check(name: string, condition: boolean, detail = ''): void {
  if (condition) {
    passed += 1;
    process.stdout.write(`  ok    ${name}\n`);
  } else {
    failed += 1;
    process.stdout.write(`  FAIL  ${name}${detail ? ` -- ${detail}` : ''}\n`);
  }
}

const app = createApp();
const server = app.listen(PORT, '127.0.0.1');
await new Promise((resolve) => server.once('listening', resolve));
const base = `http://127.0.0.1:${PORT}`;

process.stdout.write(`\nBee Bridge smoke test against ${base}\n\n`);

// ----------------------------------------------------------------- health ----

const health = await fetch(`${base}/health`);
const healthBody = (await health.json()) as Record<string, unknown>;
check('GET /health is ok', health.ok);
check('health reports the protocol version', healthBody.protocol === '2025-11-25');
check('health reports read-only', healthBody.readOnly === true);

// ------------------------------------------------------------- handshake ----

const session = await openSession(base, 'bee-smoke');

const tools = await session.listTools();
// `listTools` resolves to the JSON-RPC body itself; only `call` wraps a status.
const toolNames = (tools.result?.tools ?? []).map((t: { name: string }) => t.name);
check('serves the three Bee tools', toolNames.length === 3, `got ${toolNames.join(', ')}`);
check('exposes bee_recall', toolNames.includes('bee_recall'));
check('exposes bee_brief', toolNames.includes('bee_brief'));
check('exposes bee_status', toolNames.includes('bee_status'));
check(
  'serves no tool that could act',
  !toolNames.some((n: string) => /confirm|action|delete|run/i.test(n)),
);

// A second session must get its own id, or every later client is locked out.
const second = await openSession(base, 'bee-smoke-2');
check('each session-less POST gets its own session id', second.sessionId !== session.sessionId);

const stale = await fetch(`${base}/mcp`, {
  method: 'POST',
  headers: {
    'content-type': 'application/json',
    accept: 'application/json, text/event-stream',
    'mcp-session-id': 'not-a-real-session',
  },
  body: JSON.stringify({ jsonrpc: '2.0', id: 99, method: 'tools/list' }),
});
check('unknown session id returns 404', stale.status === 404, `got ${stale.status}`);

// --------------------------------------------------------------- recall ----

// `toolText` wants the JSON-RPC *result*, not the whole envelope.
const status = await session.call('bee_status');
const statusText = toolText(status.body?.result);
check('bee_status reaches the fake CLI', /reachable/i.test(statusText), statusText.slice(0, 160));
check('bee_status reports the refused write tool', /bee_delete_conversation/.test(statusText));
check('bee_status confirms sanitisation', /redacted, fenced/i.test(statusText));

const recall = await session.call('bee_recall', { query: 'auth', limit: 3 });
const recallText = toolText(recall.body?.result);
check('bee_recall returns transcript content', /legacy token format/.test(recallText));
check('bee_recall fences content as untrusted', /UNTRUSTED/.test(recallText));
check('bee_recall attributes the source', /Source: bee_search/.test(recallText));
check('bee_recall does not flag benign speech', !/WARNING/.test(recallText));

// A different surface should work just as well, and be a no-op rather than a
// crash when the query is not what that tool wanted.
const noResult = await session.call('bee_recall', { query: 'anything', kind: 'today' });
check('bee_recall handles the today surface', noResult.status === 200);

const brief = await session.call('bee_brief', { limit: 2 });
const briefText = toolText(brief.body?.result);
check('bee_brief returns content', /UNTRUSTED/.test(briefText), briefText.slice(0, 120));

// The injection path, against the same running server.
await scenario('injection');
const hostile = await session.call('bee_recall', { query: 'coffee' });
const hostileText = toolText(hostile.body?.result);
check(
  'a bystander instruction is reported, not obeyed',
  /WARNING/.test(hostileText) && /was not acted on/i.test(hostileText),
  hostileText.slice(0, 200),
);
check('the hostile text is still fenced', /UNTRUSTED/.test(hostileText));

await scenario('secrets');
const secrets = await session.call('bee_recall', { query: 'contact' });
const secretsText = toolText(secrets.body?.result);
check('redacts an email', !secretsText.includes('pvish@example.com'));
check('redacts a card number', !secretsText.includes('4111 1111 1111 1111'));
check('redacts an api key', !secretsText.includes('sk-live-abcdefghijklmnopqrstuvwx'));
check('reports that it redacted something', /Notes/i.test(secretsText));

// -------------------------------------------------------------- resources ----

const resources = await session.listResources();
const uris = (resources.result?.resources ?? []).map((r: { uri: string }) => r.uri);
check('serves the bee status resource', uris.includes('bridge://bee/status'), uris.join(', '));

const read = await session.read('bridge://bee/status');
// `read` also resolves to the bare JSON-RPC body, like `listTools`.
const readText = read.result?.contents?.[0]?.text ?? JSON.stringify(read);
check('the status resource is readable', /bridge/.test(readText));
check('the status resource declares the read-only surface', /readOnlyTools/.test(readText));

const prompts = await session.listPrompts();
const promptNames = (prompts.result?.prompts ?? []).map((p: { name: string }) => p.name);
check('serves the decision-context prompt', promptNames.includes('decision_context'));

// ----------------------------------------------------------------- close ----

const closed = await fetch(`${base}/mcp`, {
  method: 'DELETE',
  headers: { 'mcp-session-id': session.sessionId!, 'mcp-protocol-version': '2025-11-25' },
});
check('session termination is accepted', closed.status < 300, `got ${closed.status}`);

process.stdout.write(`\n${passed} passed, ${failed} failed\n\n`);

// Close gracefully, then exit. An immediate `process.exit()` races the listener
// teardown and can trip a libuv assertion on Windows, which makes a fully
// passing run exit non-zero.
server.close(() => {
  void closeBeeClient().finally(() => {
    setTimeout(() => process.exit(failed === 0 ? 0 : 1), 150);
  });
});
