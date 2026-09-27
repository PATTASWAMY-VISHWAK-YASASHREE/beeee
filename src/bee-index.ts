import { start } from './bee-bridge.js';

/**
 * Entry point for the Bee Bridge server.
 *
 * Same gate as `src/index.ts`: importing `./bee-bridge.js` elsewhere (tests,
 * the Inspector) builds the app without listening, so the listen call only runs
 * when this file is executed directly.
 */
const isDirectRun =
  process.argv[1] !== undefined &&
  import.meta.url === new URL(`file:///${process.argv[1].replace(/\\/g, '/')}`).href;

if (isDirectRun) {
  start();
}
