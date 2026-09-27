/**
 * Shared JSON-RPC client for the smoke test and the demo script.
 *
 * Speaks the wire format directly rather than using the SDK, so the tests
 * exercise the real handshake, session headers, and error paths.
 */
export const PROTOCOL_VERSION = '2025-11-25';

let nextId = 1;

export interface RpcResult {
  status: number;
  body: any;
  sessionId: string | null;
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
      ...(sessionId ? { 'mcp-session-id': sessionId } : {}),
    },
    body: JSON.stringify({ jsonrpc: '2.0', id: nextId++, method, ...(params ? { params } : {}) }),
  });
  const returned = res.headers.get('mcp-session-id');
  const text = await res.text();
  let body: any = text;
  try {
    body = JSON.parse(text);
  } catch {
    /* keep raw text */
  }
  return { status: res.status, body, sessionId: returned ?? sessionId };
}

/** Opens a session and returns a client bound to it. */
export async function openSession(base: string, name = 'sprig-client') {
  const init = await raw(base, 'initialize', {
    protocolVersion: PROTOCOL_VERSION,
    capabilities: {},
    clientInfo: { name, version: '0.1.0' },
  }, null);
  const sessionId = init.sessionId;

  // The initialized notification expects no response body.
  await fetch(`${base}/mcp`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      accept: 'application/json, text/event-stream',
      'mcp-session-id': sessionId!,
      'mcp-protocol-version': PROTOCOL_VERSION,
    },
    body: JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }),
  }).catch(() => undefined);

  return {
    sessionId,
    init,
    listTools: async () => (await raw(base, 'tools/list', undefined, sessionId)).body,
    listResources: async () => (await raw(base, 'resources/list', undefined, sessionId)).body,
    listPrompts: async () => (await raw(base, 'prompts/list', undefined, sessionId)).body,
    call: async (name: string, args: Record<string, unknown> = {}) => {
      const res = await raw(
        base,
        'tools/call',
        { name, arguments: args },
        sessionId,
      );
      return { status: res.status, body: res.body };
    },
    read: async (uri: string) =>
      (await raw(base, 'resources/read', { uri }, sessionId)).body,
  };
}

export type Client = Awaited<ReturnType<typeof openSession>>;

/** Flattens an MCP tool result into plain text. */
export function toolText(result: any): string {
  return (result?.content ?? [])
    .filter((c: any) => c.type === 'text')
    .map((c: any) => c.text)
    .join('\n');
}
