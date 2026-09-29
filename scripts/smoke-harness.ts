/**
 * Shared plumbing for the two smoke scripts.
 *
 * Both `smoke.ts` and `smoke-auth.ts` did the same four things -- find a free
 * port, start a listener, count PASS/FAIL lines, and tear down -- and each got
 * its own copy slightly wrong in a different way. Lifting them here means the
 * fixes are made once and neither script can drift away from them.
 */

import { createServer } from 'node:net';
import type { Server } from 'node:http';

/**
 * How long any single HTTP request may take.
 *
 * Every fetch in these scripts gets this. Without it, a server that accepts the
 * connection and then stops responding hangs the run forever with no output at
 * all -- the worst possible failure mode for a check whose entire job is to
 * tell you whether the server works. A timeout turns that into one failed
 * assertion with a name on it.
 */
export const REQUEST_TIMEOUT_MS = 15_000;

/** How long to wait for `listen` to actually bind before calling it a failure. */
export const LISTEN_TIMEOUT_MS = 10_000;

/**
 * A `fetch` with a deadline, for the raw requests the smoke scripts make.
 *
 * `AbortSignal.timeout` rather than a manual controller, because it also covers
 * the time spent waiting for a socket that never opens -- which a controller
 * wired only to the request would miss.
 */
export function timedFetch(url: string, init: RequestInit = {}): Promise<Response> {
  return fetch(url, { ...init, signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS) });
}

/**
 * Releases a response body.
 *
 * `fetch` keeps the socket alive until the body is consumed or the response is
 * cancelled. The old code called `res.status` on a dozen responses and never
 * read any of them, so every one of those sockets stayed open and `close()`
 * then waited on connections nobody was going to finish. Reading a body we do
 * not need is wasteful; cancelling it is not, and it is what lets teardown be
 * immediate.
 */
export async function discard(res: Response): Promise<void> {
  try {
    await res.body?.cancel();
  } catch {
    // Already consumed, already closed, or never had a body. Nothing to do.
  }
}

/**
 * Finds a free port, then releases it.
 *
 * The probe-then-bind dance is inherently racy -- another process can take the
 * port in between -- which is why {@link listen} attaches an error handler that
 * rejects rather than waiting forever for a 'listening' event that will never
 * arrive.
 */
export function freePort(): Promise<number> {
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

/**
 * Starts a listener and resolves once it is genuinely accepting.
 *
 * The `error` handler is the point. `await new Promise(r => server.once('listening', r))`
 * hangs forever if the bind fails, because 'error' is not the event the promise
 * is waiting for -- so an EADDRINUSE (the likely outcome of the probe race
 * above) turned into a CI job that sits there until something kills it, with
 * no diagnostic at all. Racing the two events turns it into a rejection that
 * names the cause.
 */
export function listen(app: unknown, port: number, host = '127.0.0.1'): Promise<Server> {
  return new Promise((resolve, reject) => {
    const server = (app as { listen: (p: number, h: string, cb: () => void) => Server }).listen(
      port,
      host,
      () => {
        clearTimeout(timer);
        server.off('error', onError);
        resolve(server);
      },
    );
    function onError(error: Error): void {
      clearTimeout(timer);
      reject(error);
    }
    const timer = setTimeout(() => {
      server.off('error', onError);
      reject(new Error(`The server did not bind ${host}:${port} within ${LISTEN_TIMEOUT_MS}ms`));
    }, LISTEN_TIMEOUT_MS);
    server.once('error', onError);
  });
}

/**
 * Stops a listener and resolves when it is really closed.
 *
 * `closeAllConnections()` is what replaced the fixed `setTimeout(..., 150)`
 * before `process.exit`. That sleep was a guess: too short and it raced
 * teardown into the libuv assertion on Windows, too long and it wasted time on
 * every run. Cancelling the sockets and exiting on the 'close' event is both
 * immediate and correct, because 'close' fires only once every connection is
 * finished.
 */
export function close(server: Server): Promise<void> {
  return new Promise((resolve) => {
    server.close(() => resolve());
    // Anything still open at this point is a keep-alive socket nobody is going
    // to finish writing to. Without this the close callback waits for them.
    server.closeAllConnections();
  });
}

/** Tallies PASS/FAIL lines for a smoke script and prints them. */
export class Checks {
  private passed = 0;
  private failed = 0;

  constructor(heading: string) {
    process.stdout.write(`\n${heading}\n\n`);
  }

  check(name: string, condition: boolean, detail = ''): void {
    if (condition) {
      this.passed += 1;
      process.stdout.write(`  ok    ${name}\n`);
    } else {
      this.failed += 1;
      process.stdout.write(`  FAIL  ${name}${detail ? ` -- ${detail}` : ''}\n`);
    }
  }

  /** Prints the tally and returns the exit code the script should use. */
  finish(): number {
    process.stdout.write(`\n${this.passed} passed, ${this.failed} failed\n\n`);
    return this.failed === 0 ? 0 : 1;
  }
}