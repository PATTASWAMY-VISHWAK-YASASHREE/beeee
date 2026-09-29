import { realpathSync } from 'node:fs';
import { pathToFileURL } from 'node:url';

import { ConfigError, start } from './bee-bridge.js';

/**
 * Entry point for the Bee Bridge server.
 *
 * Same gate as `src/index.ts`: importing `./bee-bridge.js` elsewhere (tests, the
 * demo script) builds the app without listening, so the listen call only runs
 * when this file is executed directly.
 *
 * Built on `pathToFileURL` rather than the hand-assembled `file:///` +
 * backslash-replace this used to do. That version was wrong in four separate
 * ways, and every one of them failed by *silently not starting* rather than by
 * crashing. `import.meta.url` is percent-encoded and the hand-built string was
 * not, so a repo path containing a space (this one does), a `#`, a `?`, or a
 * non-ASCII character produced a different string and the comparison failed; a
 * relative `process.argv[1]` was never made absolute; and an `argv[1]` that was
 * already a `file://` URL was treated as a path. Each of those exits 0 with
 * nothing listening, which to a user looks exactly like a working server.
 * `pathToFileURL` encodes precisely the way Node did, and `realpathSync`
 * resolves the symlinks and 8.3 short names that would otherwise compare
 * unequal for the very same file.
 */
function isDirectRun(): boolean {
  const invoked = process.argv[1];
  if (invoked === undefined) return false;
  try {
    // Some launchers hand us a URL rather than a path (node --import, a
    // debugger, a custom loader). Normalise first, or a genuine direct run
    // looks like an import and we exit having started nothing.
    const entry = invoked.startsWith('file:') ? invoked : pathToFileURL(invoked).href;
    if (import.meta.url === entry) return true;
    // Second chance, through the real path. Cheap, and it is what catches a
    // symlinked checkout or a Windows short-name invocation.
    return import.meta.url === pathToFileURL(realpathSync(entry)).href;
  } catch {
    // An argv[1] we cannot resolve is not this file. False is the safe
    // direction: the module still works for anyone who imports it.
    return false;
  }
}

if (isDirectRun()) {
  try {
    const server = start();

    // `start()` installs its own handler -- it is the one that knows the port
    // and can say "already in use, set BEE_BRIDGE_PORT" -- but a listener error
    // is an *event*, never a throw, so no try/catch above would ever see one.
    // Attaching a second handler here means the process still reports a
    // bind failure cleanly no matter how `start()` is later refactored, rather
    // than reverting to an unhandled 'error' event and a bare stack trace.
    server.on('error', (error: NodeJS.ErrnoException) => {
      process.stderr.write(
        `[bee-bridge] listener error (${error.code ?? 'UNKNOWN'}): ${error.message}\n`,
      );
      process.exit(1);
    });
  } catch (error) {
    // A config error is the operator's to fix and its message is the entire
    // answer -- printing a stack trace for `BEE_BRIDGE_PORT=banana` buries it.
    // Anything else is a real crash and deserves the full story.
    if (error instanceof ConfigError) {
      process.stderr.write(`[bee-bridge] configuration error: ${error.message}\n`);
      process.exit(1);
    }
    process.stderr.write(`[bee-bridge] failed to start: ${String(error)}\n`);
    if (error instanceof Error && error.stack) process.stderr.write(`${error.stack}\n`);
    process.exit(1);
  }
}
