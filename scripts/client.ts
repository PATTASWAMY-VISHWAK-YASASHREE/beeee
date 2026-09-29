/**
 * Shared JSON-RPC client for the smoke test and the demo script.
 *
 * Speaks the wire format directly rather than using the SDK, so the tests
 * exercise the real handshake, session headers, and error paths.
 */
export const PROTOCOL_VERSION = '2025-11-25';

/** Ceiling on a single response body. See {@link readBody}. */
const MAX_RESPONSE_BYTES = 4 * 1024 * 1024;

/** Deadline for one request/response round trip. */
const REQUEST_TIMEOUT_MS = 15_000;

let nextId = 1;

/**
 * The JSON-RPC envelope, as much of it as this client actually reads.
 *
 * Typed rather than `any` on purpose. A smoke test whose whole value is "the
 * server sent the right shape" cannot be `any`: a malformed response then flows
 * straight into an assertion and produces a FAIL that blames the server for a
 * bug in the test -- or, worse, an `ok` because `undefined?.result` happened not
 * to throw. `unknown` plus these guards means a wrong shape is caught as a
 * wrong shape, here, where the diagnosis is still obvious.
 */
export interface JsonRpcEnvelope {
  jsonrpc?: string;
  id?: string | number | null;
  result?: unknown;
  error?: { code?: number; message?: string; data?: unknown };
}

export interface RpcResult {
  status: number;
  /** The parsed envelope, or the raw text when it was neither JSON nor SSE. */
  body: unknown;
  sessionId: string | null;
}

/** Narrows an unknown value to an envelope that carries a `result`. */
export function asResult(body: unknown): JsonRpcEnvelope | null {
  if (typeof body !== 'object' || body === null) return null;
  const envelope = body as JsonRpcEnvelope;
  return 'result' in envelope ? envelope : null;
}

/** Reads a string field off an unknown value, or undefined. */
function str(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined;
}

/** Pulls the payloads out of a `text/event-stream` body. */
function parseSse(text: string): unknown {
  const messages: unknown[] = [];
  for (const block of text.split(/\r?\n\r?\n/)) {
    // SSE allows several `data:` lines per event and the spec joins them with a
    // newline, which is what a JSON payload split across lines needs.
    const data = block
      .split(/\r?\n/)
      .filter((line) => line.startsWith('data:'))
      .map((line) => line.slice(5).trimStart())
      .join('\n');
    if (!data || data === '[DONE]') continue;
    try {
      messages.push(JSON.parse(data));
    } catch {
      // An unreadable frame is no reason to discard the ones we can read.
    }
  }
  if (messages.length === 0) return undefined;
  // A single event is the overwhelmingly common case; returning it unwrapped
  // saves every caller from unwrapping an array that is almost always length 1.
  return messages.length === 1 ? messages[0] : messages;
}

/**
 * Turns a response body into an envelope.
 *
 * The SSE branch is the one that matters. This client advertises
 * `accept: application/json, text/event-stream`, which is exactly what the spec
 * asks for, and a perfectly compliant server may answer with
 * `text/event-stream`. The old code only tried `JSON.parse`, so an SSE reply
 * left `body` as the raw `data: {...}` text, every `.result` read came back
 * `undefined`, and the smoke test reported a server failure for a server that
 * was behaving correctly -- a false failure against the most protocol-correct
 * server imaginable. Decoding SSE properly is the right fix; narrowing the
 * accept header to dodge the case would just make the test weaker.
 */
function parseBody(text: string, contentType: string | null): unknown {
  if (text.trim() === '') return null;
  const trimmed = text.trim();
  if (contentType?.includes('text/event-stream') || trimmed.startsWith('data:')) {
    const parsed = parseSse(trimmed);
    if (parsed !== undefined) return parsed;
  }
  try {
    return JSON.parse(trimmed);
  } catch {
    // Neither JSON nor SSE. Hand the text back, so a caller asserting on the
    // failure can see what actually arrived rather than nothing at all.
    return text;
  }
}

/**
 * Reads a response body under a size cap and a deadline.
 *
 * `await res.text()` was doing two unsafe things at once. It has no ceiling, so
 * a misbehaving or hostile server can make this process buffer without limit --
 * and the test harness is the last thing that should be trivially DoS-able. And
 * it carries no deadline of its own, so a server that sends headers and then
 * stalls hangs the run. The abort signal covers the stall; the reader covers the
 * size, and cancelling the stream is what releases the socket.
 */
async function readBody(res: Response): Promise<string> {
  const body = res.body;
  if (!body) return '';
  const reader = body.getReader();
  const decoder = new TextDecoder();
  let text = '';
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      text += decoder.decode(value, { stream: true });
      if (text.length > MAX_RESPONSE_BYTES) {
        // Stop pulling immediately. Continuing to read "just to be sure" is
        // precisely how a cap stops being a cap.
        await reader.cancel().catch(() => undefined);
        throw new Error(`Response body exceeded ${MAX_RESPONSE_BYTES} bytes`);
      }
    }
    return text + decoder.decode();
  } finally {
    reader.releaseLock();
  }
}

async function raw(
  base: string,
  method: string,
  params: unknown,
  sessionId: string | null,
): Promise<RpcResult> {
  const res = await fetch(`${base}/mcp`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      // The spec requires clients to advertise both, even for a JSON response.
      accept: 'application/json, text/event-stream',
      // The spec requires MCP-Protocol-Version on every request *after* the
      // handshake, not only on the one that carries the session id. It was only
      // being sent alongside the initialized notification, so a strict server is
      // entitled to reject every tools/list this client sends -- a failure that
      // would look like a server bug and be entirely the harness's.
      'mcp-protocol-version': PROTOCOL_VERSION,
      ...(sessionId ? { 'mcp-session-id': sessionId } : {}),
    },
    body: JSON.stringify({ jsonrpc: '2.0', id: nextId++, method, ...(params ? { params } : {}) }),
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  });
  const returned = res.headers.get('mcp-session-id');
  const text = await readBody(res);
  return {
    status: res.status,
    body: parseBody(text, res.headers.get('content-type')),
    sessionId: returned ?? sessionId,
  };
}

/**
 * Turns a response into an envelope, throwing if it was not a success.
 *
 * The list and read helpers used to return `.body` directly, discarding the HTTP
 * status. A 404, a 401, and a JSON-RPC `error` member were then all
 * indistinguishable from a well-formed result, and the callers' `?? []` quietly
 * turned every one of them into an empty list that most assertions accept. That
 * is a check that cannot fail for the reason it was written, which is the worst
 * kind of check there is. Throwing here means a broken server produces a named
 * error at the call site instead of a silent empty array three lines later.
 */
function unwrap(res: RpcResult, what: string): JsonRpcEnvelope {
  const envelope = asResult(res.body);
  if (res.status >= 400) {
    const detail =
      typeof res.body === 'string'
        ? res.body.slice(0, 200)
        : (str((res.body as JsonRpcEnvelope | null)?.error?.message) ?? 'no detail');
    throw new Error(`${what} failed: HTTP ${res.status} (${detail})`);
  }
  if (envelope) return envelope;
  const message = str((res.body as JsonRpcEnvelope | null)?.error?.message);
  if (message) throw new Error(`${what} returned a JSON-RPC error: ${message}`);
  throw new Error(`${what} returned no result member: ${String(res.body).slice(0, 200)}`);
}

/** Opens a session and returns a client bound to it. */
export async function openSession(base: string, name = 'sprig-client') {
  const init = await raw(
    base,
    'initialize',
    {
      protocolVersion: PROTOCOL_VERSION,
      capabilities: {},
      clientInfo: { name, version: '0.1.0' },
    },
    null,
  );

  // The handshake is validated, not assumed. A rejected initialize used to
  // still hand back a "client" with `sessionId: null`, and every later call
  // then went out with no session header -- which, now that only `initialize`
  // may open a session, means a 400 on the very next request. Diagnosing that
  // from the far end is guesswork; diagnosing it here, at the one place it went
  // wrong, is a one-line stack.
  if (init.status >= 400) {
    throw new Error(
      `initialize was rejected: HTTP ${init.status} ${String(init.body).slice(0, 200)}`,
    );
  }
  const initResult = asResult(init.body);
  if (!initResult) {
    throw new Error(`initialize returned no result: ${String(init.body).slice(0, 200)}`);
  }
  if (typeof (initResult.result as { protocolVersion?: unknown } | null)?.protocolVersion !== 'string') {
    throw new Error('initialize result is missing protocolVersion');
  }
  const sessionId = init.sessionId;
  if (!sessionId) {
    // Without this the client is bound to nothing, and every subsequent call
    // silently opens a brand-new session -- which is exactly the unbounded
    // allocation the server was changed to prevent, re-introduced from the
    // other direction.
    throw new Error('initialize returned no Mcp-Session-Id header');
  }

  // Awaited, and checked. This used to be fire-and-forget behind a `catch` that
  // swallowed the outcome, so a server that rejected the notification let the
  // failure surface much later as a confusing "Server not initialized" on the
  // next tools/list. Several implementations refuse tools/list until they have
  // seen it, so not awaiting makes the client's very next call a coin flip.
  const ready = await fetch(`${base}/mcp`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      accept: 'application/json, text/event-stream',
      'mcp-session-id': sessionId,
      'mcp-protocol-version': PROTOCOL_VERSION,
    },
    body: JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }),
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
  });
  await ready.body?.cancel().catch(() => undefined);
  if (ready.status >= 400) {
    throw new Error(`the initialized notification was rejected: HTTP ${ready.status}`);
  }

  return {
    sessionId,
    init,
    // These throw on a bad response rather than returning a body the caller has
    // to remember to check. See `unwrap` for why that matters here.
    listTools: async () => unwrap(await raw(base, 'tools/list', undefined, sessionId), 'tools/list'),
    listResources: async () =>
      unwrap(await raw(base, 'resources/list', undefined, sessionId), 'resources/list'),
    listPrompts: async () =>
      unwrap(await raw(base, 'prompts/list', undefined, sessionId), 'prompts/list'),
    call: async (toolName: string, args: Record<string, unknown> = {}) => {
      const res = await raw(base, 'tools/call', { name: toolName, arguments: args }, sessionId);
      return { status: res.status, body: res.body };
    },
    read: async (uri: string) =>
      unwrap(await raw(base, 'resources/read', { uri }, sessionId), 'resources/read'),
  };
}

export type Client = Awaited<ReturnType<typeof openSession>>;

/** Flattens an MCP tool result into plain text, guarding the content array. */
export function toolText(result: unknown): string {
  if (typeof result !== 'object' || result === null) return '';
  const content = (result as { content?: unknown }).content;
  if (!Array.isArray(content)) return '';
  return content
    .filter((entry): entry is { type: 'text'; text: string } => {
      const c = entry as { type?: unknown; text?: unknown };
      return c.type === 'text' && typeof c.text === 'string';
    })
    .map((c) => c.text)
    .join('\n');
}
