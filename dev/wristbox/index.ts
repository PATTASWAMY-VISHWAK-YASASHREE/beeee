import { start } from './server.js';

/**
 * Entry point for the Wristbox stand-in.
 *
 * Separate from `server.ts` for the same reason `src/index.ts` is separate from
 * `src/server.ts`: importing the server to build the app in a test must not
 * open a port.
 */
const isDirectRun =
  process.argv[1] !== undefined &&
  import.meta.url === new URL(`file:///${process.argv[1].replace(/\\/g, '/')}`).href;

if (isDirectRun) {
  start();
}
