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
 * A note on how to read a green run here. Every check in this file is written so
 * that deleting the thing it protects makes it fail. That is the only property
 * that distinguishes a test from a comment, and it is why the DNS-rebinding block
 * sends a real request with a disallowed Host header rather than asserting that
 * the option is set somewhere in the source.
 *
 * Run with: npm run smoke
 */

import { request as httpRequest } from 'node:http';
import type { Server } from 'node:http';
import { fileURLToPath } from 'node:url';

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
 * allow-list from the port, and that protection is a spec MUST -- so listening
 * on some other port makes every MCP call fail with a 403, which is the server
 * working correctly. The probe-then-bind dance is how we test it without
 * hard-coding a port that may already be taken.
 */
const {
  freePort,
  listen,
  close,
  timedFetch,
  discard,
  Checks,
  REQUEST_TIMEOUT_MS,
} = await import('./smoke-harness.js');

const PORT = await freePort();
process.env.BEE_BRIDGE_PORT = String(PORT);

const { createApp, setBoundPort } = await import('../src/bee-bridge.js');
const { closeBeeClient } = await import('../src/bee/tools.js');
const { openSession, toolText, asResult } = await import('./client.js');

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

const checks = new Checks('Bee Bridge smoke test');

/**
 * Runs the body, then always tears down and reports an honest exit code.
 *
 * Declared outside the try because `finally` needs it: a `const` inside the try
 * would not be in scope there, which is the same reason the old teardown could
 * be skipped on a throw in the first place.
 */
let server: Server | null = null;
let exitCode = 1;
try {
  // `listen` rejects on a bind error and times out rather than waiting for a
  // 'listening' event that will never arrive. See smoke-harness for why.
  server = await listen(createApp(), PORT);
  // Tell the server which port it actually got, so the DNS-rebinding allow-list
  // is built from the bound socket rather than from the configured constant.
  setBoundPort(PORT);
  const base = `http://127.0.0.1:${PORT}`;

  checks.check('the server bound a real port', server.address() !== null);

  process.stdout.write(`Target: ${base}\n\n`);

  // ---------------------------------------------------------------- health ----

  const health = await timedFetch(`${base}/health`);
  const healthBody = (await health.json()) as Record<string, unknown>;
  checks.check('GET /health is ok', health.ok);
  checks.check('health reports the protocol version', healthBody.protocol === '2025-11-25');
  checks.check('health reports read-only', healthBody.readOnly === true);
  // /health is unauthenticated, so it must not hand out the absolute path of the
  // Bee binary: that discloses the OS account name and install directory to
  // anything that can reach loopback, including any web page. The basename still
  // answers the question an operator actually has.
  checks.check(
    'health does not leak the absolute Bee path',
    typeof healthBody.beeBinary === 'string' &&
      !healthBody.beeBinary.includes('\\') &&
      !healthBody.beeBinary.includes('/'),
    String(healthBody.beeBinary),
  );

  // ------------------------------------------------------------- handshake ----

  const session = await openSession(base, 'bee-smoke');

  const tools = await session.listTools();
  // `listTools` returns the JSON-RPC envelope; `result` is the interesting part.
  const toolNames = ((tools.result as { tools?: { name: string }[] } | undefined)?.tools ?? []).map(
    (t) => t.name,
  );
  checks.check('serves the three Bee tools', toolNames.length === 3, `got ${toolNames.join(', ')}`);
  checks.check('exposes bee_recall', toolNames.includes('bee_recall'));
  checks.check('exposes bee_brief', toolNames.includes('bee_brief'));
  checks.check('exposes bee_status', toolNames.includes('bee_status'));
  checks.check(
    'serves no tool that could act',
    !toolNames.some((n) => /confirm|action|delete|run/i.test(n)),
  );

  // A second handshake must get its own id, or every later client is locked out.
  // Note the wording: an *initialize* gets its own session. The check further
  // down is the one that pins down why that distinction matters.
  const second = await openSession(base, 'bee-smoke-2');
  checks.check('each initialize gets its own session id', second.sessionId !== session.sessionId);

  // ------------------------------------------------- DNS-rebinding (spec MUST) ----

  // This block is the one that was missing, and its absence mattered more than
  // any other gap in this file. `smoke.ts` claimed in its own header comment to
  // cover DNS rebinding, but no request in it ever used a disallowed Host
  // header. Deleting `allowedHosts` from the server -- removing a protection the
  // spec requires outright -- left this suite fully green. A test that cannot
  // fail when the thing it tests is deleted is decoration.
  //
  // `fetch` cannot express this: undici derives Host from the URL and ignores an
  // attempt to override it, so a spoofed Host needs `node:http`.
  const postWithHost = (host: string) =>
    new Promise<number>((resolve, reject) => {
      const body = JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'initialize',
        params: {
          protocolVersion: '2025-11-25',
          capabilities: {},
          clientInfo: { name: 'rebind-probe', version: '0.1.0' },
        },
      });
      const request = httpRequest(
        {
          host: '127.0.0.1',
          port: PORT,
          path: '/mcp',
          method: 'POST',
          headers: {
            Host: host,
            // Both are load-bearing. Without the content-type the body parser
            // leaves `req.body` empty, so the server sees a request that is
            // neither an initialize nor a recognised method and answers 400 --
            // which would make the *legitimate* host check below fail for a
            // reason that has nothing to do with DNS rebinding. That is exactly
            // how a probe ends up measuring the wrong thing.
            'content-type': 'application/json',
            accept: 'application/json, text/event-stream',
            'content-length': Buffer.byteLength(body),
          },
        },
        (res) => {
          res.resume(); // drain, so the socket can close
          resolve(res.statusCode ?? 0);
        },
      );
      request.on('error', reject);
      request.setTimeout(REQUEST_TIMEOUT_MS, () => request.destroy(new Error('timed out')));
      request.end(body);
    });

  // The attack: a page on evil.test resolves its own domain to 127.0.0.1 and
  // posts to the bridge. Binding to loopback does not stop that, which is
  // exactly why the spec makes an allow-list a MUST.
  const rebound = await postWithHost('evil.test');
  checks.check(
    'a request with a hostile Host header is refused with 403',
    rebound === 403,
    `got ${rebound}`,
  );

  // The other half, and it is the half people forget: the check above passes
  // just as happily if the allow-list is broken so badly that *everything* is
  // rejected. Without this, "always 403" would score identically to "correct".
  const legitimate = await postWithHost(`localhost:${PORT}`);
  checks.check(
    'the same request with an allowed Host succeeds',
    legitimate === 200,
    `got ${legitimate}`,
  );

  // --------------------------------------------------------- session contract ----

  // A POST with no session id and no initialize must be refused, not served by
  // quietly minting a new session. Before this rule existed, this exact request
  // allocated a whole McpServer and a transport, and repeating it grew the
  // process without bound.
  //
  // The *message* is asserted, not just the status, and that is deliberate. The
  // MCP transport has its own 400 for a session-less non-initialize request, so
  // a status-only check here passes with or without our guard -- it would prove
  // nothing about the guard at all. What distinguishes the two is that ours
  // refuses *before* allocating anything, so it names the fix, and it hands
  // back no session id. A check that cannot tell "we refused" from "something
  // downstream refused after we had already built the thing" is not checking
  // the thing this finding is about.
  const noSession = await timedFetch(`${base}/mcp`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 42, method: 'tools/list' }),
  });
  const noSessionBody = (await noSession.json().catch(() => null)) as {
    error?: { message?: string };
  } | null;
  await discard(noSession);
  checks.check(
    'a session-less non-initialize POST is refused with 400',
    noSession.status === 400,
    `got ${noSession.status}`,
  );
  checks.check(
    'that refusal happens before any session is allocated',
    /Mcp-Session-Id header is required/.test(noSessionBody?.error?.message ?? '') &&
      noSession.headers.get('mcp-session-id') === null,
    `message was "${noSessionBody?.error?.message ?? 'none'}"`,
  );

  const stale = await timedFetch(`${base}/mcp`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      accept: 'application/json, text/event-stream',
      'mcp-session-id': 'not-a-real-session',
      'mcp-protocol-version': '2025-11-25',
    },
    body: JSON.stringify({ jsonrpc: '2.0', id: 99, method: 'tools/list' }),
  });
  await discard(stale);
  checks.check('unknown session id returns 404', stale.status === 404, `got ${stale.status}`);

  // A batch carrying a tools/list alongside the initialize must not be allowed
  // to open a session, or "only initialize opens a session" is true solely for
  // requests that happen to be well behaved.
  const smuggled = await timedFetch(`${base}/mcp`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', accept: 'application/json, text/event-stream' },
    body: JSON.stringify([
      {
        jsonrpc: '2.0',
        id: 1,
        method: 'initialize',
        params: {
          protocolVersion: '2025-11-25',
          capabilities: {},
          clientInfo: { name: 'smuggler', version: '0.1.0' },
        },
      },
      { jsonrpc: '2.0', id: 2, method: 'tools/list' },
    ]),
  });
  await discard(smuggled);
  checks.check(
    'a batch mixing initialize with another method is refused',
    smuggled.status === 400,
    `got ${smuggled.status}`,
  );

  // --------------------------------------------------------------- recall ----

  // `toolText` wants the JSON-RPC *result*, not the whole envelope.
  const status = await session.call('bee_status');
  const statusText = toolText(asResult(status.body)?.result);
  checks.check('bee_status reaches the fake CLI', /reachable/i.test(statusText), statusText.slice(0, 160));
  checks.check('bee_status reports the refused write tool', /bee_delete_conversation/.test(statusText));
  checks.check('bee_status confirms sanitisation', /redacted, fenced/i.test(statusText));

  const recall = await session.call('bee_recall', { query: 'auth', limit: 3 });
  const recallText = toolText(asResult(recall.body)?.result);
  checks.check('bee_recall returns transcript content', /legacy token format/.test(recallText));
  checks.check('bee_recall fences content as untrusted', /UNTRUSTED/.test(recallText));
  checks.check('bee_recall attributes the source', /Source: bee_search/.test(recallText));
  checks.check('bee_recall does not flag benign speech', !/WARNING/.test(recallText));

  // A different surface should work just as well, and be a no-op rather than a
  // crash when the query is not what that tool wanted.
  const noResult = await session.call('bee_recall', { query: 'anything', kind: 'today' });
  checks.check('bee_recall handles the today surface', noResult.status === 200);

  const brief = await session.call('bee_brief', { limit: 2 });
  const briefText = toolText(asResult(brief.body)?.result);
  checks.check('bee_brief returns content', /UNTRUSTED/.test(briefText), briefText.slice(0, 120));

  // The injection path, against the same running server.
  await scenario('injection');
  const hostile = await session.call('bee_recall', { query: 'coffee' });
  const hostileText = toolText(asResult(hostile.body)?.result);
  checks.check(
    'a bystander instruction is reported, not obeyed',
    /WARNING/.test(hostileText) && /was not acted on/i.test(hostileText),
    hostileText.slice(0, 200),
  );
  checks.check('the hostile text is still fenced', /UNTRUSTED/.test(hostileText));

  await scenario('secrets');
  const secrets = await session.call('bee_recall', { query: 'contact' });
  const secretsText = toolText(asResult(secrets.body)?.result);
  checks.check('redacts an email', !secretsText.includes('pvish@example.com'));
  checks.check('redacts a card number', !secretsText.includes('4111 1111 1111 1111'));
  checks.check('redacts an api key', !secretsText.includes('sk-live-abcdefghijklmnopqrstuvwx'));

  // The three checks above are all "the secret is gone", and all three pass
  // against a server that dropped the transcript entirely. The disclosure check
  // used to be `/Notes/i`, which also matches the word "Notes" appearing
  // anywhere -- including incidentally, in a header, in prose, in a filename.
  // That means the exact regression this suite exists to catch, a sanitiser that
  // silently removed content without saying so, would have left it green.
  //
  // What we assert instead is the contract itself: the exact section header, a
  // bulleted line beneath it, and at least the specific kinds that were
  // redacted. A redactor that quietly stopped reporting now fails.
  checks.check(
    'reports redactions under the exact Notes header',
    /Notes \(these matter\):/.test(secretsText),
    secretsText.slice(0, 300),
  );
  checks.check(
    'each reported redaction is bulleted',
    /Notes \(these matter\):\s*\n- \S/.test(secretsText),
  );
  const reportedKinds = ['email address', 'card number', 'api token', 'phone number'].filter((kind) =>
    new RegExp(`- [^\\n]*${kind}`, 'i').test(secretsText),
  );
  checks.check(
    'names the specific kinds it redacted',
    reportedKinds.length >= 2,
    `only reported: ${reportedKinds.join(', ') || 'none'}`,
  );
  // A mask must be visible. Silent deletion would make the redaction invisible
  // to the user, who would then read it as "Bee has nothing on this".
  checks.check(
    'leaves a visible mask in place of each secret',
    /\[(email|card number|phone number|token|api key) redacted\]/.test(secretsText),
  );

  // -------------------------------------------------------------- resources ----

  const resources = await session.listResources();
  const uris = (
    (resources.result as { resources?: { uri: string }[] } | undefined)?.resources ?? []
  ).map((r) => r.uri);
  checks.check('serves the bee status resource', uris.includes('bridge://bee/status'), uris.join(', '));

  const read = await session.read('bridge://bee/status');
  const readText =
    (read.result as { contents?: { text?: string }[] } | undefined)?.contents?.[0]?.text ??
    JSON.stringify(read);
  checks.check('the status resource is readable', /bridge/.test(readText));
  checks.check('the status resource declares the read-only surface', /readOnlyTools/.test(readText));

  const prompts = await session.listPrompts();
  const promptNames = (
    (prompts.result as { prompts?: { name: string }[] } | undefined)?.prompts ?? []
  ).map((p) => p.name);
  checks.check('serves the decision-context prompt', promptNames.includes('decision_context'));

  // ----------------------------------------------------------------- close ----

  const closed = await timedFetch(`${base}/mcp`, {
    method: 'DELETE',
    headers: { 'mcp-session-id': session.sessionId, 'mcp-protocol-version': '2025-11-25' },
  });
  await discard(closed);
  checks.check('session termination is accepted', closed.status < 300, `got ${closed.status}`);

  exitCode = checks.finish();
} catch (error) {
  // A throw here is a harness or server failure, not a failed assertion, and the
  // distinction has to survive into the exit code. Reporting it as a plain FAIL
  // would bury the stack that explains everything.
  process.stderr.write(`\n  ERROR ${String(error)}\n`);
  if (error instanceof Error && error.stack) process.stderr.write(`${error.stack}\n`);
  checks.check('the smoke run completed without throwing', false, String(error));
  exitCode = 1;
} finally {
  // try/finally, not a trailing block: previously any throw skipped
  // `server.close()` entirely and left the `bee` child process running, which on
  // Windows is a process nobody can see and CI cannot reap.
  if (server) await close(server).catch(() => undefined);
  await closeBeeClient().catch(() => undefined);
}

process.exit(exitCode);
