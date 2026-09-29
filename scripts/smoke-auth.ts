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
import type { Server } from 'node:http';

/**
 * 48 characters, comfortably over the 32 the server now enforces at startup.
 * It has to be: the server refuses to bind with a shorter one, so a token that
 * used to "work" now stops the process from starting at all. That is the
 * intended behaviour, and this constant is the evidence of it.
 */
const TOKEN = 'test-token-abcdefghijklmnopqrstuvwxyz-0123456789';
process.env.BEE_BRIDGE_TOKEN = TOKEN;
process.env.BEE_BIN = process.execPath;
process.chdir(fileURLToPath(new URL('../tests/fixtures/', import.meta.url)));
process.env.FAKE_BEE_SCENARIO = 'normal';

const { freePort, listen, close, timedFetch, discard, Checks } = await import(
  './smoke-harness.js'
);

const PORT = await freePort();
process.env.BEE_BRIDGE_PORT = String(PORT);

const { createApp, setBoundPort } = await import('../src/bee-bridge.js');

const checks = new Checks('Bee Bridge auth smoke test (token set)');

/** A credential that is well formed and simply not the right one. */
const WRONG_TOKEN = 'wrong-token-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';

/** The server, torn down in `finally` whatever happens below. */
let server: Server | null = null;
let exitCode = 1;
let base = '';

const post = (headers: Record<string, string>, method = 'tools/list') =>
  timedFetch(`${base}/mcp`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      accept: 'application/json, text/event-stream',
      'mcp-protocol-version': '2025-11-25',
      ...headers,
    },
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

try {
  // `listen` rejects on a bind failure and times out rather than waiting for a
  // 'listening' event that will never arrive. See smoke-harness for why.
  server = await listen(createApp(), PORT);
  setBoundPort(PORT);
  base = `http://127.0.0.1:${PORT}`;

  process.stdout.write(`Target: ${base}\n\n`);

  // Each of these consumes its response. An unread body keeps the socket open,
  // which is what made the old teardown wait and needed a 150ms sleep to paper
  // over it.

  const anonymous = await post({});
  await discard(anonymous);
  checks.check('no token is refused', anonymous.status === 401, `got ${anonymous.status}`);
  // This check used to send NO authorization header at all, which made it
  // byte-for-byte identical to the "no token" check above. It never exercised a
  // present-but-wrong credential, so a regression that accepted any well-formed
  // Bearer value would have passed both. The distinction between "you sent
  // nothing" and "you sent the wrong thing" is the entire point of a constant-
  // time comparison, so the test has to make it.
  const wrong = await post({ authorization: `Bearer ${WRONG_TOKEN}` }, 'initialize');
  await discard(wrong);
  checks.check(
    'a present-but-wrong token is refused',
    wrong.status === 401,
    `got ${wrong.status}`,
  );

  // And the near-miss: a token of the right *length* but the wrong bytes. A
  // length-only comparison -- the classic bug when `timingSafeEqual` throws on
  // mismatched buffer lengths and someone "fixes" it by checking length alone --
  // would let this through.
  const sameLength = await post(
    { authorization: `Bearer ${'x'.repeat(TOKEN.length)}` },
    'initialize',
  );
  await discard(sameLength);
  checks.check(
    'a wrong token of the correct length is refused',
    sameLength.status === 401,
    `got ${sameLength.status}`,
  );

  const malformed = await post({ authorization: TOKEN });
  await discard(malformed);
  checks.check(
    'a non-bearer authorization header is refused',
    malformed.status === 401,
    `got ${malformed.status}`,
  );

  // The demo must stay reachable, or a judge cannot see any of this.
  const health = await timedFetch(`${base}/health`);
  await discard(health);
  checks.check('health stays open', health.status === 200, `got ${health.status}`);

  // The accepting call has to be a real handshake. Sending `tools/list` on a
  // brand-new session gets past auth and then fails with "Server not
  // initialized" -- which would look like a broken token check rather than the
  // protocol detail it actually is.
  //
  // The body is parsed and asserted, not just the status. Status and a session
  // header were the whole of the old check, and both are satisfied by a 200
  // carrying a JSON-RPC `error` member, or by an initialize result with no
  // protocolVersion -- neither of which is a working server. "Authenticated" and
  // "the handshake succeeded" are separate claims, and only the first one is
  // about the token.
  const accepted = await post({ authorization: `Bearer ${TOKEN}` }, 'initialize');
  const acceptedBody = (await accepted.json().catch(() => null)) as {
    result?: { protocolVersion?: unknown };
    error?: { message?: string };
  } | null;
  await discard(accepted);

  checks.check('the correct token is accepted', accepted.status === 200, `got ${accepted.status}`);
  checks.check(
    'the accepted call returns a session id',
    Boolean(accepted.headers.get('mcp-session-id')),
  );
  checks.check(
    'the accepted call returns no JSON-RPC error',
    acceptedBody !== null && acceptedBody.error === undefined,
    acceptedBody?.error?.message ?? 'body was not JSON',
  );
  checks.check(
    'the handshake reports a protocol version',
    typeof acceptedBody?.result?.protocolVersion === 'string',
    `protocolVersion was ${String(acceptedBody?.result?.protocolVersion)}`,
  );

  exitCode = checks.finish();
} catch (error) {
  process.stderr.write(`\n  ERROR ${String(error)}\n`);
  if (error instanceof Error && error.stack) process.stderr.write(`${error.stack}\n`);
  checks.check('the auth smoke run completed without throwing', false, String(error));
  exitCode = 1;
} finally {
  // try/finally: any throw used to skip server.close() entirely, and the `bee`
  // child this script spawns would be left running with nothing holding it.
  if (server) await close(server).catch(() => undefined);
}

process.exit(exitCode);
