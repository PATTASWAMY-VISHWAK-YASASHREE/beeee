import { spawn, type ChildProcessWithoutNullStreams } from 'node:child_process';
import { randomUUID } from 'node:crypto';

/**
 * MCP client for the `bee` CLI -- Amazon's wearable AI assistant.
 *
 * ## Why this file exists, and why it is so defensive
 *
 * Everything Hermes Bridge knows about a person comes from here. Bee is a
 * wearable that listens to the room it is in: it transcribes ambient
 * conversations, identifies speakers, and keeps the result end-to-end encrypted
 * personal history. That makes it simultaneously (a) the most useful input the
 * project could possibly have, and (b) the single most dangerous input it will
 * ever touch.
 *
 * Two consequences drive every design decision below.
 *
 * **1. The trust boundary stops at the tool name.** The `bee` MCP server does
 * not only read. It can also *manage* the user's data: create and complete
 * todos, edit or delete stored facts, rewrite summaries. If Hermes Bridge could
 * reach those tools, then a single mistranscribed sentence, a bad retrieval
 * result, or a prompt injection smuggled inside somebody else's spoken words
 * could rewrite the user's own memory. So this client is not a general MCP
 * client. It refuses, by name, every tool that is not on {@link READ_ONLY_TOOLS},
 * before a single byte is written to the wire. The allowlist is a hard
 * constant, not configuration, and it is intentionally *narrow*: adding to it is
 * a security decision that belongs in review, not a runtime toggle.
 *
 * **2. "Read-only" is a claim about the tool, not about us.** The allowlist is
 * only as good as our reading of Bee's tool set, and this file was written
 * against a hackathon CLI we cannot audit. That is a real limitation, not a
 * formality, so the code is built to fail closed: process spawn is argv-only
 * with no shell, every request is bounded by a hard timeout that kills the whole
 * process tree, response bodies are capped so a runaway cannot exhaust memory,
 * and the HTTP transport refuses any endpoint that is not loopback and refuses
 * any bearer token shorter than the 32 characters `bee serve-http` itself
 * requires.
 *
 * ## Deliberate non-goals
 *
 * - No reconnect, no retry, no backoff. A half-open stdio pipe cannot be
 *   resynchronised safely; a caller that wants a fresh session makes a new
 *   client. Guessing here would be worse than failing.
 * - No streaming responses. Voice wants one bounded answer, not a token feed.
 * - No resources, prompts, or sampling. This client is a tool caller and
 *   nothing else.
 */

export const BEE_BIN = process.env.BEE_BIN ?? 'bee';

/** Pinned rather than inherited, matching `server.ts` and the 2025-11-25 spec. */
export const PROTOCOL_VERSION = '2025-11-25';

const CLIENT_INFO = { name: 'hermes-bridge-bee-client', version: '0.1.0' } as const;

/**
 * The only Bee tools this process is permitted to call.
 *
 * Every entry is a read. There is deliberately no `bee_manage_*` tool here
 * even where one would be convenient: writing to a user's own wearable memory
 * from inside a voice-driven agent is the failure mode this whole file exists to
 * prevent.
 */
export const READ_ONLY_TOOLS: readonly string[] = Object.freeze([
  'bee_search',
  'bee_list_facts',
  'bee_get_daily_summary',
  'bee_get_conversation',
  'bee_list_todos',
  'bee_today',
  'bee_now',
  'bee_get_facts',
  'bee_get_todo',
  'bee_get_now',
]);

const READ_ONLY_TOOL_SET: ReadonlySet<string> = new Set(READ_ONLY_TOOLS);

/**
 * Tool names we believe are mutating, kept purely so the refusal can say
 * something useful ("that one writes to your Bee") instead of a flat no.
 *
 * This list grants nothing. An unknown tool is refused exactly like a known
 * write tool, because we cannot verify what an unrecognised tool does.
 */
export const KNOWN_WRITE_TOOLS: readonly string[] = Object.freeze([
  'bee_create_todo',
  'bee_update_todo',
  'bee_complete_todo',
  'bee_delete_todo',
  'bee_add_fact',
  'bee_update_fact',
  'bee_delete_fact',
  'bee_manage_facts',
  'bee_manage_todos',
]);

/** Voice cannot usefully absorb a megabyte of transcript, so replies are capped. */
export const MAX_RESPONSE_CHARS = Number(process.env.BEE_MAX_RESPONSE_CHARS ?? 20_000);

/** Args for one tool call are small by nature; cap them so nothing odd ships out. */
export const MAX_ARG_CHARS = Number(process.env.BEE_MAX_ARG_CHARS ?? 8_000);

const DEFAULT_TIMEOUT_MS = Number(process.env.BEE_TIMEOUT_MS ?? 20_000);

/**
 * Default port for `bee mcp serve-http`. Deliberately *not* this project's own
 * `PORT` (8790): if a developer forgets to set anything, we must not end up
 * talking to ourselves.
 */
const DEFAULT_HTTP_PORT = Number(process.env.BEE_MCP_HTTP_PORT ?? 8788);

/** `bee serve-http` refuses bearer tokens shorter than this. We refuse too. */
export const MIN_HTTP_TOKEN_CHARS = 32;

/** Guards against a malformed or hostile process flooding us with one huge line. */
const MAX_STDIO_LINE_CHARS = 4 * 1024 * 1024;

/** Same idea for the HTTP side, where a loopback server is still a remote peer. */
const MAX_HTTP_BODY_CHARS = 2 * 1024 * 1024;

/** Non-JSON chatter (banners, warnings) is kept, but only this much of it. */
const MAX_LOG_CHARS = 8_000;

/** `tools/list` is paginated; refuse to loop forever on a broken server. */
const MAX_LIST_PAGES = 5;

export type BeeTransportKind = 'stdio' | 'http';

/** Every failure this client raises carries one of these codes. */
export type BeeErrorCode =
  | 'bad_config'
  | 'missing_token'
  | 'weak_token'
  | 'non_loopback_endpoint'
  | 'tool_not_read_only'
  | 'args_too_large'
  | 'client_closed'
  | 'transport_lost'
  | 'spawn_failed'
  | 'handshake_failed'
  | 'timeout'
  | 'http_unauthorized'
  | 'http_status'
  | 'session_expired'
  | 'malformed_response'
  | 'rpc_error';

/** Codes that mean "this was refused on purpose", as opposed to "it broke". */
export type BeePolicyCode = Extract<
  BeeErrorCode,
  | 'bad_config'
  | 'missing_token'
  | 'weak_token'
  | 'non_loopback_endpoint'
  | 'tool_not_read_only'
  | 'args_too_large'
>;

export class BeeError extends Error {
  readonly code: BeeErrorCode;
  constructor(message: string, code: BeeErrorCode) {
    super(message);
    this.name = 'BeeError';
    this.code = code;
  }
}

/**
 * A refusal by design, not a malfunction. Callers can surface these to the user
 * verbatim: they describe what the bridge will not do and why.
 */
export class BeePolicyError extends BeeError {
  constructor(message: string, code: BeePolicyCode) {
    super(message, code);
    this.name = 'BeePolicyError';
  }
}

/** The process, socket, or handshake failed. Retrying is the caller's problem. */
export class BeeTransportError extends BeeError {
  constructor(message: string, code: BeeErrorCode) {
    super(message, code);
    this.name = 'BeeTransportError';
  }
}

/** The server answered, and its answer was "no". */
export class BeeRpcError extends BeeError {
  readonly rpcCode: number;
  readonly data: unknown;
  constructor(message: string, rpcCode: number, data?: unknown) {
    super(message, 'rpc_error');
    this.name = 'BeeRpcError';
    this.rpcCode = rpcCode;
    this.data = data;
  }
}

/** True only for the tools on {@link READ_ONLY_TOOLS}. */
export function isReadOnlyTool(name: string): boolean {
  return READ_ONLY_TOOL_SET.has(name);
}

export interface BeeToolInfo {
  name: string;
  description?: string;
  inputSchema?: unknown;
}

/** One MCP content block, kept deliberately loose because Bee owns the shape. */
export interface BeeContentBlock {
  type: string;
  text?: string;
  mimeType?: string;
  data?: string;
}

export interface BeeToolResult {
  /** The tool that produced this, echoed back so logs need no extra plumbing. */
  tool: string;
  /** All text blocks joined with newlines, capped at {@link MAX_RESPONSE_CHARS}. */
  text: string;
  /** Non-text blocks passed through so callers can decide what to do with them. */
  content: BeeContentBlock[];
  /**
   * MCP reports tool-level failures in-band with `isError: true` rather than as
   * a JSON-RPC error. We pass that through instead of throwing, because "Bee
   * said it has no such conversation" is an answer, not a transport failure.
   */
  isError: boolean;
  /** True when text was cut to fit the cap. Never silent: say so out loud. */
  truncated: boolean;
  /** Length of the joined text before capping, so callers can show a real ratio. */
  originalChars: number;
  durationMs: number;
}

export interface BeeServerInfo {
  name?: string;
  version?: string;
  protocolVersion: string;
}

export interface BeeClientOptions {
  /** Defaults to `BEE_MCP_TRANSPORT`, then `stdio`. */
  transport?: BeeTransportKind;
  /** Defaults to {@link BEE_BIN} (`bee` on PATH, or `$BEE_BIN`). */
  binary?: string;
  /**
   * Extra argv appended after `mcp serve`, as separate elements. Never
   * interpolated into a command line, and never use it to pass a secret: argv
   * is world-readable in the process table on most systems.
   */
  extraArgs?: string[];
  /** Full endpoint for the HTTP transport. Defaults to `BEE_MCP_HTTP_URL`. */
  endpoint?: string;
  /** Bearer token for the HTTP transport. Defaults to `BEE_MCP_HTTP_TOKEN`. */
  token?: string;
  /** Handshake and default per-call budget. */
  timeoutMs?: number;
  /** Test seam. Defaults to the global `fetch`. */
  fetchImpl?: typeof fetch;
}

/** What the transport needs to do for one JSON-RPC message. */
interface BeeTransport {
  readonly kind: BeeTransportKind;
  /** Sends a request and resolves the matching JSON-RPC `result`. */
  request(method: string, params: unknown, timeoutMs: number): Promise<unknown>;
  /** Sends a notification. Fire-and-forget; servers answer with 202. */
  notify(method: string, params: unknown, timeoutMs: number): Promise<void>;
  close(): Promise<void>;
  /** A short human-readable summary for logs and error messages. */
  describe(): string;
}

/** A JSON-RPC id. Kept as a string so stdio and HTTP share one map key type. */
type RpcId = string;

interface JsonRpcResponse {
  jsonrpc?: string;
  id?: RpcId | number | null;
  result?: unknown;
  error?: { code?: number; message?: string; data?: unknown };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Turns anything a server sent into the one shape callers are allowed to see. */
function coerceBlock(value: unknown): BeeContentBlock | null {
  if (!isRecord(value)) return null;
  const type = typeof value['type'] === 'string' ? value['type'] : 'unknown';
  const block: BeeContentBlock = { type };
  if (typeof value['text'] === 'string') block.text = value['text'];
  if (typeof value['mimeType'] === 'string') block.mimeType = value['mimeType'];
  if (typeof value['data'] === 'string') block.data = value['data'];
  return block;
}

/** Normalises a JSON-RPC id from the wire into our string key. */
function idKey(id: unknown): string | null {
  if (typeof id === 'string') return id;
  if (typeof id === 'number' && Number.isFinite(id)) return String(id);
  return null;
}

/**
 * Kills a child and everything it spawned.
 *
 * `bee mcp serve` may itself start helpers that inherit the stdio pipes, so
 * killing only the direct child can leave the pipes open and the client hanging
 * forever. `taskkill /T /F` is the Windows equivalent of a process-group kill;
 * elsewhere SIGKILL on the direct child is the best portable approximation.
 */
function killTree(child: ChildProcessWithoutNullStreams): void {
  try {
    if (process.platform === 'win32' && child.pid) {
      spawn('taskkill', ['/pid', String(child.pid), '/T', '/F'], {
        windowsHide: true,
        shell: false,
        stdio: 'ignore',
      });
    } else {
      child.kill('SIGKILL');
    }
  } catch {
    // Best effort. If the process is already gone this throws, and that is fine.
    try {
      child.kill();
    } catch {
      /* nothing left to do */
    }
  }
}

/**
 * MCP over stdio: `bee mcp serve` on stdin/stdout, one JSON message per line.
 *
 * Two details are easy to get wrong and are handled explicitly here:
 *
 * 1. **Framing.** A byte stream chops mid-message, so writes must be
 *    newline-terminated and reads must buffer until a newline actually arrives.
 *    Reading with a naive `chunk -> JSON.parse` loses the first message
 *    whenever two happen to arrive in one read.
 * 2. **Purity of the channel.** stdout is the protocol; stderr is for humans.
 *    We capture stderr into a bounded tail and never let it contaminate the
 *    parse path, and any non-JSON line on stdout is logged rather than thrown
 *    away, because a startup banner should not kill the session.
 */
class StdioTransport implements BeeTransport {
  readonly kind = 'stdio' as const;

  private readonly child: ChildProcessWithoutNullStreams;
  private readonly pending = new Map<
    RpcId,
    { resolve: (v: unknown) => void; reject: (e: Error) => void; timer: NodeJS.Timeout }
  >();
  private buffer = '';
  private nextId = 0;
  private closed = false;
  private failure: BeeTransportError | null = null;
  /** Bounded tail of stderr and non-JSON stdout, surfaced in error messages. */
  private log = '';

  constructor(binary: string, extraArgs: readonly string[]) {
    this.child = spawn(binary, ['mcp', 'serve', ...extraArgs], {
      windowsHide: true,
      // Explicitly false, not merely omitted. Everything Bee can read is
      // end-to-end encrypted personal data, so there is no scenario in which an
      // argument is worth handing to a shell interpreter. This also keeps a
      // search phrase from becoming shell syntax.
      shell: false,
      stdio: ['pipe', 'pipe', 'pipe'],
      env: { ...process.env, NO_COLOR: '1' },
    });

    this.child.stdout.setEncoding('utf8');
    this.child.stderr.setEncoding('utf8');
    this.child.stdout.on('data', (chunk: string) => this.ingest(chunk));
    this.child.stderr.on('data', (chunk: string) => this.note(String(chunk)));
    this.child.on('error', (error: NodeJS.ErrnoException) => {
      this.fail(
        error.code === 'ENOENT'
          ? new BeeTransportError(
              `Could not find "${binary}" on PATH. Install the Bee CLI, or set BEE_BIN to its full path.`,
              'spawn_failed',
            )
          : new BeeTransportError(`bee mcp serve failed to start: ${error.message}`, 'spawn_failed'),
      );
    });
    this.child.on('close', (code, signal) => {
      this.fail(
        new BeeTransportError(
          `bee mcp serve exited (code ${code ?? 'null'}, signal ${signal ?? 'none'}).${this.log ? ` Last output: ${this.log}` : ''}`,
          'transport_lost',
        ),
      );
    });
  }

  /** Resolves once the process exists, so ENOENT surfaces as a clean error. */
  ready(timeoutMs: number): Promise<void> {
    return new Promise<void>((resolve, reject) => {
      const timer = setTimeout(() => {
        reject(new BeeTransportError(`bee mcp serve did not start within ${timeoutMs}ms.`, 'timeout'));
      }, timeoutMs);
      this.child.once('spawn', () => {
        clearTimeout(timer);
        resolve();
      });
      this.child.once('error', () => {
        clearTimeout(timer);
        // The constructor's own handler has already latched a typed error by
        // now (listener order guarantees it), so prefer that over the raw
        // NodeJS error. Callers should only ever have to catch BeeError.
        reject(
          this.failure ?? new BeeTransportError('bee mcp serve failed to start.', 'spawn_failed'),
        );
      });
    });
  }

  request(method: string, params: unknown, timeoutMs: number): Promise<unknown> {
    const id = `r${++this.nextId}`;
    return new Promise<unknown>((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        // The pipe is now in an unknown state: a late reply for this id would
        // be delivered to nobody, and a subsequent id could be misread if the
        // server restarted. Killing the tree is the only way to guarantee the
        // channel stays consistent, so a timeout is fatal for this transport.
        this.fail(
          new BeeTransportError(
            `bee mcp serve did not answer ${method} within ${timeoutMs}ms.${this.log ? ` Last output: ${this.log}` : ''}`,
            'timeout',
          ),
        );
        reject(new BeeTransportError(`Bee did not answer ${method} in time.`, 'timeout'));
      }, timeoutMs);

      this.pending.set(id, { resolve, reject, timer });
      try {
        this.write({ jsonrpc: '2.0', id, method, params });
      } catch (error) {
        clearTimeout(timer);
        this.pending.delete(id);
        reject(error instanceof Error ? error : new BeeTransportError(String(error), 'transport_lost'));
      }
    });
  }

  async notify(method: string, params: unknown, _timeoutMs: number): Promise<void> {
    this.write({ jsonrpc: '2.0', method, params });
  }

  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    killTree(this.child);
    this.drain();
  }

  describe(): string {
    return `stdio:${this.child.spawnfile} mcp serve`;
  }

  private write(message: Record<string, unknown>): void {
    if (this.failure) throw this.failure;
    if (this.closed) {
      throw new BeeTransportError('This Bee client is closed.', 'client_closed');
    }
    // `shell: false` above means this is a direct pipe write: no quoting, no
    // escaping, no opportunity for the payload to become code.
    this.child.stdin.write(`${JSON.stringify(message)}\n`, 'utf8');
  }

  /** Splits the stream on newlines and dispatches each complete message. */
  private ingest(chunk: string): void {
    this.buffer += chunk;
    if (this.buffer.length > MAX_STDIO_LINE_CHARS) {
      // Something is emitting megabytes without a newline. Refusing beats
      // growing the buffer until the process dies of memory pressure.
      this.buffer = '';
      this.fail(
        new BeeTransportError(
          'bee mcp serve sent more than 4MB without a newline; the stream is not valid MCP. Closing it.',
          'malformed_response',
        ),
      );
      return;
    }

    for (;;) {
      const newline = this.buffer.indexOf('\n');
      if (newline === -1) return;
      const line = this.buffer.slice(0, newline).trim();
      this.buffer = this.buffer.slice(newline + 1);
      if (line) this.dispatch(line);
    }
  }

  private dispatch(line: string): void {
    let parsed: unknown;
    try {
      parsed = JSON.parse(line);
    } catch {
      // A banner, a warning, a deprecation notice. Not fatal, and definitely not
      // something to discard quietly.
      this.note(line);
      return;
    }

    // JSON-RPC 2.0 batches are deprecated but legal, and a server is free to
    // ignore the spec and send one anyway. Handle both shapes.
    const messages = Array.isArray(parsed) ? parsed : [parsed];
    for (const message of messages) {
      if (isRecord(message)) this.settle(message as JsonRpcResponse);
    }
  }

  private settle(message: JsonRpcResponse): void {
    // Server-initiated notifications (logging, progress) carry no id. We have
    // nothing to do with them, and ignoring them is correct.
    const key = idKey(message.id);
    if (key === null) return;

    const waiter = this.pending.get(key);
    if (!waiter) return; // Late reply to something we already gave up on.
    this.pending.delete(key);
    clearTimeout(waiter.timer);

    if (message.error) {
      const code = typeof message.error.code === 'number' ? message.error.code : -32603;
      waiter.reject(new BeeRpcError(message.error.message ?? 'Bee returned an error.', code, message.error.data));
      return;
    }
    waiter.resolve(message.result);
  }

  /** Latches the first failure and tears everything down exactly once. */
  private fail(error: BeeTransportError): void {
    if (this.failure) return;
    this.failure = error;
    this.closed = true;
    this.drain();
  }

  private drain(): void {
    for (const [, waiter] of this.pending) {
      clearTimeout(waiter.timer);
      waiter.reject(this.failure ?? new BeeTransportError('This Bee client is closed.', 'client_closed'));
    }
    this.pending.clear();
  }

  /** Keeps a bounded tail of human-readable output for error messages. */
  private note(text: string): void {
    this.log = (this.log + text).slice(-MAX_LOG_CHARS);
  }
}


/** Rejects any endpoint that is not loopback. */
function assertLoopback(endpoint: string): URL {
  let url: URL;
  try {
    url = new URL(endpoint);
  } catch {
    throw new BeePolicyError(
      `BEE_MCP_HTTP_URL is not a valid URL: "${endpoint}".`,
      'bad_config',
    );
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new BeePolicyError(
      `Bee MCP must be reached over http or https, not "${url.protocol}".`,
      'bad_config',
    );
  }
  // A remote endpoint would mean shipping somebody's encrypted personal history
  // off-box, or worse, accepting commands from the network. `bee serve-http`
  // binds 127.0.0.1 for the same reason, and so do we.
  const host = url.hostname.toLowerCase();
  const loopback =
    host === 'localhost' ||
    host === '::1' ||
    host === '[::1]' ||
    /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host);
  if (!loopback) {
    throw new BeePolicyError(
      `Refusing to talk to Bee at ${url.origin}: it is not on this machine. Hermes Bridge only reads Bee over loopback, because Bee holds end-to-end encrypted personal conversation data.`,
      'non_loopback_endpoint',
    );
  }
  return url;
}

/** Mirrors `bee serve-http`'s own rule. A short token is a token we will not send. */
function assertToken(token: string): string {
  if (!token) {
    throw new BeePolicyError(
      'BEE_MCP_HTTP_TOKEN is required for the http transport. Start Bee with `bee mcp serve-http --token <at least 32 characters>`.',
      'missing_token',
    );
  }
  if (token.length < MIN_HTTP_TOKEN_CHARS) {
    throw new BeePolicyError(
      `BEE_MCP_HTTP_TOKEN is ${token.length} characters; Bee requires at least ${MIN_HTTP_TOKEN_CHARS}. Refusing to send a guessable bearer token.`,
      'weak_token',
    );
  }
  return token;
}

/**
 * Pulls the JSON-RPC response out of an HTTP reply.
 *
 * Streamable HTTP allows the server to answer with either `application/json`
 * or, when it wants to stream, `text/event-stream`. Bee's own implementation
 * uses SSE, so the SSE path is not optional here -- but a plain JSON body is
 * equally legal, so both are handled. An SSE body is a sequence of `data:` lines
 * separated by blank lines; we take the first frame that carries our id.
 */
function parseRpcBody(body: string, contentType: string, wantId: RpcId | null): JsonRpcResponse {
  const isEventStream = contentType.toLowerCase().includes('text/event-stream');

  if (!isEventStream) {
    try {
      const parsed: unknown = JSON.parse(body);
      if (isRecord(parsed)) return parsed as JsonRpcResponse;
      throw new Error('not an object');
    } catch {
      throw new BeeTransportError('Bee returned a body that is not a JSON-RPC object.', 'malformed_response');
    }
  }

  // Split on the SSE record separator. `\r\n\r\n` and `\n\n` both occur in the
  // wild depending on the server, so normalise CRLF first.
  const frames = body.replace(/\r\n/g, '\n').split('\n\n');
  let sawFrame = false;
  for (const frame of frames) {
    const data = frame
      .split('\n')
      .filter((line) => line.startsWith('data:'))
      .map((line) => line.slice(5).trimStart())
      .join('\n');
    if (!data) continue;
    sawFrame = true;

    let parsed: unknown;
    try {
      parsed = JSON.parse(data);
    } catch {
      continue; // A keep-alive or a partial frame. Look at the next one.
    }
    if (!isRecord(parsed)) continue;
    const message = parsed as JsonRpcResponse;
    // Progress notifications arrive first and carry no id; skip past them.
    if (wantId !== null && idKey(message.id) !== wantId) continue;
    return message;
  }

  throw new BeeTransportError(
    sawFrame
      ? 'Bee\'s event stream carried no answer to our request.'
      : 'Bee returned an event stream with no data frames.',
    'malformed_response',
  );
}

/**
 * MCP over Streamable HTTP, pointed at `bee mcp serve-http`.
 *
 * This transport is a *client* to a server the user started themselves, so
 * there is no process for us to manage and no stream to keep in sync. What it
 * inherits from the stdio path is the discipline: loopback only, a token long
 * enough to be worth having, a hard per-request timeout, and a body size cap.
 *
 * One protocol detail matters and is easy to miss: the server hands back a
 * session id on `initialize` and expects it on every later request. Dropping it
 * is the usual cause of "the handshake worked and then every call 404s".
 */
class HttpTransport implements BeeTransport {
  readonly kind = 'http' as const;

  private readonly url: URL;
  private readonly token: string;
  private readonly fetchImpl: typeof fetch;
  private nextId = 0;
  private sessionId: string | null = null;
  private closed = false;

  constructor(endpoint: string, token: string, fetchImpl: typeof fetch) {
    this.url = assertLoopback(endpoint);
    this.token = assertToken(token);
    this.fetchImpl = fetchImpl;
  }

  async request(method: string, params: unknown, timeoutMs: number): Promise<unknown> {
    const id = `h${++this.nextId}`;
    const message = await this.post({ jsonrpc: '2.0', id, method, params }, timeoutMs, id);
    if (message.error) {
      const code = typeof message.error.code === 'number' ? message.error.code : -32603;
      throw new BeeRpcError(message.error.message ?? 'Bee returned an error.', code, message.error.data);
    }
    return message.result;
  }

  async notify(method: string, params: unknown, timeoutMs: number): Promise<void> {
    // A notification gets 202 with no body by spec. A 200 with a body is
    // tolerated but ignored, because there is no id to correlate anyway.
    await this.post({ jsonrpc: '2.0', method, params }, timeoutMs, null);
  }

  async close(): Promise<void> {
    this.closed = true;
  }

  describe(): string {
    return `http://${this.url.host}${this.url.pathname}`;
  }

  private async post(
    payload: Record<string, unknown>,
    timeoutMs: number,
    wantId: RpcId | null,
  ): Promise<JsonRpcResponse> {
    if (this.closed) {
      throw new BeeTransportError('This Bee client is closed.', 'client_closed');
    }

    // An explicit AbortController is the honest way to bound a fetch: it cancels
    // the underlying socket, not just the promise, so a slow server cannot leave
    // a request dangling after we have given up on it.
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    let response: Response;
    try {
      response = await this.fetchImpl(this.url, {
        method: 'POST',
        headers: this.headers(),
        body: JSON.stringify(payload),
        signal: controller.signal,
        cache: 'no-store',
      });
    } catch (error) {
      const aborted = controller.signal.aborted;
      throw new BeeTransportError(
        aborted
          ? `Bee did not answer within ${timeoutMs}ms.`
          : `Could not reach Bee at ${this.describe()}: ${(error as Error).message}`,
        aborted ? 'timeout' : 'http_status',
      );
    } finally {
      clearTimeout(timer);
    }

    this.captureSession(response);

    if (response.status === 401 || response.status === 403) {
      throw new BeeTransportError(
        'Bee rejected our bearer token. Check that BEE_MCP_HTTP_TOKEN matches the one you started `bee mcp serve-http` with.',
        'http_unauthorized',
      );
    }
    if (response.status === 404 && this.sessionId) {
      throw new BeeTransportError(
        'Bee no longer knows this session. Restart `bee mcp serve-http` and create a new client.',
        'session_expired',
      );
    }
    if (!response.ok) {
      throw new BeeTransportError(
        `Bee answered HTTP ${response.status} ${response.statusText} for ${String(payload['method'])}.`,
        'http_status',
      );
    }

    // Notifications, and some rejections, carry no body at all.
    const body = await this.readBounded(response);
    if (!body.trim()) {
      if (wantId === null) return {};
      throw new BeeTransportError(
        `Bee answered ${String(payload['method'])} with an empty body.`,
        'malformed_response',
      );
    }
    return parseRpcBody(body, response.headers.get('content-type') ?? '', wantId);
  }

  private headers(): Record<string, string> {
    const headers: Record<string, string> = {
      'content-type': 'application/json',
      // Both types are advertised because Streamable HTTP permits either, and
      // omitting one makes some servers pick badly.
      accept: 'application/json, text/event-stream',
      authorization: `Bearer ${this.token}`,
      'mcp-protocol-version': PROTOCOL_VERSION,
    };
    if (this.sessionId) headers['mcp-session-id'] = this.sessionId;
    return headers;
  }

  /** Remembers the session id the server hands out during `initialize`. */
  private captureSession(response: Response): void {
    const id = response.headers.get('mcp-session-id');
    if (id) this.sessionId = id;
  }

  /**
   * Reads a response body with a hard ceiling.
   *
   * `response.text()` will happily buffer whatever it is handed. Even over
   * loopback that is a denial-of-service waiting to happen, so we stream and
   * abort rather than trusting a `content-length` header.
   */
  private async readBounded(response: Response): Promise<string> {
    const body = response.body;
    if (!body) return '';

    const reader = body.getReader();
    const decoder = new TextDecoder('utf-8');
    let out = '';
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        out += decoder.decode(value, { stream: true });
        if (out.length > MAX_HTTP_BODY_CHARS) {
          await reader.cancel().catch(() => undefined);
          throw new BeeTransportError(
            `Bee sent more than ${MAX_HTTP_BODY_CHARS} characters; refusing to buffer it.`,
            'malformed_response',
          );
        }
      }
      return out + decoder.decode();
    } finally {
      reader.releaseLock();
    }
  }
}

/**
 * A read-only MCP session against the `bee` CLI.
 *
 * Construct with {@link BeeClient.connect}, which performs the full
 * `initialize` / `notifications/initialized` handshake before resolving. A
 * half-open client is never handed out: the alternative is a client that
 * accepts calls and fails them mysteriously later.
 *
 * ## What this class will not do
 *
 * It will not call a tool outside {@link READ_ONLY_TOOLS}, it will not write to
 * the user's Bee, and it will not reach a Bee running on another machine. Those
 * are enforced, not documented-and-hoped-for. See the file header for why the
 * tool-name allowlist is the actual trust boundary here.
 *
 * ## Lifetime
 *
 * Long-lived and not auto-recovering. A failed stdio call kills the process
 * tree, because a desynchronised JSON-RPC stream cannot be repaired in place;
 * call {@link close} and {@link BeeClient.connect} again. For HTTP, the failure
 * is per-request and the client stays usable.
 */
export class BeeClient {
  private readonly transport: BeeTransport;
  private readonly defaultTimeoutMs: number;
  private serverInfo: BeeServerInfo | null = null;
  private closed = false;

  private constructor(transport: BeeTransport, defaultTimeoutMs: number) {
    this.transport = transport;
    this.defaultTimeoutMs = defaultTimeoutMs;
  }

  /**
   * Opens a session and completes the MCP handshake.
   *
   * The handshake is not optional ceremony: the spec requires
   * `notifications/initialized` before a server will serve any other method, and
   * skipping it produces a client that 404s on the first real call. We also
   * record the negotiated protocol version rather than assuming ours won, so a
   * version mismatch shows up in logs instead of as mysterious parse errors.
   */
  static async connect(options: BeeClientOptions = {}): Promise<BeeClient> {
    const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    const kind = options.transport ?? (process.env.BEE_MCP_TRANSPORT as BeeTransportKind | undefined) ?? 'stdio';
    if (kind !== 'stdio' && kind !== 'http') {
      throw new BeePolicyError(
        `BEE_MCP_TRANSPORT must be "stdio" or "http", not "${String(kind)}".`,
        'bad_config',
      );
    }

    const transport: BeeTransport =
      kind === 'http'
        ? new HttpTransport(
            options.endpoint ?? process.env.BEE_MCP_HTTP_URL ?? `http://127.0.0.1:${DEFAULT_HTTP_PORT}/mcp`,
            options.token ?? process.env.BEE_MCP_HTTP_TOKEN ?? '',
            options.fetchImpl ?? globalThis.fetch,
          )
        : new StdioTransport(options.binary ?? BEE_BIN, options.extraArgs ?? []);

    const client = new BeeClient(transport, timeoutMs);
    try {
      if (transport instanceof StdioTransport) await transport.ready(timeoutMs);
      await client.handshake();
    } catch (error) {
      // Never leak a half-started process or a dangling session on failure.
      await transport.close().catch(() => undefined);
      throw error;
    }
    return client;
  }

  /** Which transport this session is using, for status output and logs. */
  get kind(): BeeTransportKind {
    return this.transport.kind;
  }

  /** What the server said about itself during the handshake. */
  get info(): BeeServerInfo | null {
    return this.serverInfo;
  }

  /**
   * Lists the tools Bee advertises.
   *
   * Note the deliberate asymmetry with {@link callTool}: this is discovery, not
   * permission. The list will include write tools, because hiding them would be
   * a lie about what Bee can do. {@link callTool} is where the allowlist bites.
   */
  async listTools(options: { timeoutMs?: number } = {}): Promise<BeeToolInfo[]> {
    this.assertOpen();
    const timeoutMs = options.timeoutMs ?? this.defaultTimeoutMs;
    const tools: BeeToolInfo[] = [];
    let cursor: string | undefined;

    for (let page = 0; page < MAX_LIST_PAGES; page += 1) {
      const result = await this.transport.request(
        'tools/list',
        cursor ? { cursor } : {},
        timeoutMs,
      );
      if (!isRecord(result)) {
        throw new BeeTransportError('tools/list did not return an object.', 'malformed_response');
      }
      const list = Array.isArray(result['tools']) ? result['tools'] : [];
      for (const entry of list) {
        const tool = coerceTool(entry);
        if (tool) tools.push(tool);
      }
      const next = result['nextCursor'];
      if (typeof next !== 'string' || !next) return tools;
      cursor = next;
    }

    throw new BeeTransportError(
      `tools/list is still paginating after ${MAX_LIST_PAGES} pages. Treating it as broken rather than looping forever.`,
      'malformed_response',
    );
  }

  /**
   * Calls a read-only Bee tool.
   *
   * This is the security boundary, and it is enforced before the allowlist
   * check, before argument validation, and before anything touches the
   * transport. There is no flag, option, or environment variable that turns it
   * off -- if you find yourself wanting one, the answer is that the bridge
   * should not be the thing writing to somebody's personal memory.
   *
   * Throws {@link BeePolicyError} for any tool not on {@link READ_ONLY_TOOLS},
   * including every `bee_manage_*` and write tool, and including tools we have
   * never heard of. An unrecognised tool is refused precisely because we cannot
   * verify what it does.
   */
  async callTool(
    name: string,
    args: Record<string, unknown> = {},
    options: { timeoutMs?: number } = {},
  ): Promise<BeeToolResult> {
    this.assertOpen();
    assertReadOnly(name);
    const checkedArgs = assertArgs(args);

    const timeoutMs = options.timeoutMs ?? this.defaultTimeoutMs;
    const started = Date.now();
    const result = await this.transport.request(
      'tools/call',
      { name, arguments: checkedArgs },
      timeoutMs,
    );

    return normaliseToolResult(name, result, Date.now() - started);
  }

  /**
   * Ends the session.
   *
   * Idempotent, and safe to call from a `finally`. For stdio this kills the
   * process tree, because leaving an orphaned `bee mcp serve` holding the user's
   * decrypted session open would be the worst available outcome.
   */
  async close(): Promise<void> {
    if (this.closed) return;
    this.closed = true;
    await this.transport.close();
  }

  /** A one-line description of this session, for status tools and logs. */
  describe(): string {
    return `bee via ${this.transport.describe()}`;
  }

  /** `initialize`, then the mandatory `notifications/initialized`. */
  private async handshake(): Promise<void> {
    const result = await this.transport.request(
      'initialize',
      {
        protocolVersion: PROTOCOL_VERSION,
        // We advertise no roots, sampling, or elicitation. This client only
        // calls tools, so there is nothing else to offer, and nothing else for
        // a prompt injection to try to borrow.
        capabilities: {},
        clientInfo: CLIENT_INFO,
      },
      this.defaultTimeoutMs,
    );

    if (!isRecord(result)) {
      throw new BeeTransportError('Bee did not answer initialize with an object.', 'handshake_failed');
    }
    const server = isRecord(result['serverInfo']) ? result['serverInfo'] : {};
    this.serverInfo = {
      name: typeof server['name'] === 'string' ? server['name'] : undefined,
      version: typeof server['version'] === 'string' ? server['version'] : undefined,
      protocolVersion:
        typeof result['protocolVersion'] === 'string' ? result['protocolVersion'] : PROTOCOL_VERSION,
    };

    // Required by the spec before any other method is served. If this throws,
    // `connect` closes the transport, so we never sit in a limbo state.
    await this.transport.notify('notifications/initialized', {}, this.defaultTimeoutMs);
  }

  private assertOpen(): void {
    if (this.closed) {
      throw new BeeTransportError(
        'This Bee client is closed. Open a new one with BeeClient.connect().',
        'client_closed',
      );
    }
  }
}

/** The allowlist gate, isolated so the reasoning lives in exactly one place. */
function assertReadOnly(name: string): void {
  if (isReadOnlyTool(name)) return;

  const hint = KNOWN_WRITE_TOOLS.includes(name)
    ? 'That tool writes to your Bee, and this bridge only ever reads from it.'
    : 'This bridge cannot verify what that tool does, so it refuses it by default.';
  throw new BeePolicyError(
    `Bee tool "${name}" is not on the read-only allowlist. ${hint} ` +
      `Tools this bridge may call: ${READ_ONLY_TOOLS.join(', ')}.`,
    'tool_not_read_only',
  );
}

/**
 * Bounds the argument object.
 *
 * Two reasons. A runaway caller should fail here rather than after writing a
 * megabyte into a pipe. And `JSON.stringify` is where a cyclic object blows up,
 * so doing it eagerly turns an obscure "Converting circular structure to JSON"
 * from deep inside a transport into a clean, attributable message.
 */
function assertArgs(args: Record<string, unknown>): Record<string, unknown> {
  if (!isRecord(args)) {
    throw new BeePolicyError('Tool arguments must be a JSON object.', 'bad_config');
  }
  let serialised: string | undefined;
  try {
    serialised = JSON.stringify(args);
  } catch {
    throw new BeePolicyError('Tool arguments are not JSON-serialisable (circular?).', 'bad_config');
  }
  if (serialised === undefined) {
    throw new BeePolicyError('Tool arguments are not JSON-serialisable.', 'bad_config');
  }
  if (serialised.length > MAX_ARG_CHARS) {
    throw new BeePolicyError(
      `Tool arguments are ${serialised.length} characters; the limit is ${MAX_ARG_CHARS}. Ask Bee a narrower question.`,
      'args_too_large',
    );
  }
  return args;
}

/** A `tools/list` entry that is missing a name is not a tool. Skip it. */
function coerceTool(value: unknown): BeeToolInfo | null {
  if (!isRecord(value)) return null;
  const name = value['name'];
  if (typeof name !== 'string' || !name) return null;
  const tool: BeeToolInfo = { name };
  if (typeof value['description'] === 'string') tool.description = value['description'];
  if (value['inputSchema'] !== undefined) tool.inputSchema = value['inputSchema'];
  return tool;
}

/**
 * Turns a `tools/call` result into something a caller can safely print.
 *
 * The cap is the point of this function. A single `bee_get_conversation` on a
 * long day can return tens of thousands of characters of other people's
 * speech, and this client is one hop away from a voice reply and a model
 * context window. Truncation is therefore *reported*, never silent: the caller
 * gets `truncated: true` and a truthful `originalChars`, so it can say
 * "here is the first 20,000 characters" instead of quietly pretending that was
 * everything.
 */
function normaliseToolResult(tool: string, result: unknown, durationMs: number): BeeToolResult {
  if (!isRecord(result)) {
    throw new BeeTransportError(`Bee returned a non-object result for ${tool}.`, 'malformed_response');
  }

  const blocks: BeeContentBlock[] = [];
  const rawContent = Array.isArray(result['content']) ? result['content'] : [];
  for (const entry of rawContent) {
    const block = coerceBlock(entry);
    if (block) blocks.push(block);
  }

  const joined = blocks
    .map((block) => (typeof block.text === 'string' ? block.text : ''))
    .filter((text) => text.length > 0)
    .join('\n');

  const truncated = joined.length > MAX_RESPONSE_CHARS;
  return {
    tool,
    text: truncated ? joined.slice(0, MAX_RESPONSE_CHARS) : joined,
    content: blocks,
    isError: result['isError'] === true,
    truncated,
    originalChars: joined.length,
    durationMs,
  };
}

