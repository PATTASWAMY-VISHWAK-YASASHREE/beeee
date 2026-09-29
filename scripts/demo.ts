/**
 * One-command demo against the fixture `bee`, for when there is no hardware.
 *
 * The real track needs the wearable, the app, and Developer Mode. This exists
 * so a judge, a reviewer, or you on a train can still see the whole trust
 * boundary working end to end.
 *
 *     npm run demo              # benign conversation
 *     npm run demo:attack       # the injection scenario
 *     npm run demo:secrets      # the redaction scenario
 *
 * The scenario names below are the *npm script* names, not arguments. The
 * doc block used to say `npm run demo -- attack`, which does not exist: there
 * is no `attack` scenario (it is called `injection`) and the scripts are
 * `demo:attack` / `demo:secrets`. Copying that line verbatim printed
 * `Unknown scenario "attack"` and exited 1, which is a poor first impression for
 * the one entry point meant to be foolproof.
 *
 * The scenario has to be set in-process, before the server module loads, for
 * the same reason the smoke tests set it there: the setting is read by the
 * fixture process at startup, so exporting it in the surrounding shell is not
 * enough to be sure it arrives.
 */

import { fileURLToPath } from 'node:url';

/**
 * Where the fixture `bee` lives. The client spawns `<binary> mcp serve` and
 * Node resolves that leading `mcp` against the working directory, so the chdir
 * below is load-bearing rather than cosmetic. See tests/fixtures/mcp for the
 * full explanation of why the launcher is called what it is.
 */
const FIXTURES = fileURLToPath(new URL('../tests/fixtures/', import.meta.url));

/**
 * What each scenario demonstrates, and the copy the banner prints.
 *
 * `as const` is what makes the two a single source of truth. The whitelist used
 * to be a separate `Set(['normal', 'injection', ...])` next to a separate object
 * literal, so renaming a key or adding a scenario to one and not the other
 * produced a demo that either rejected a valid name or printed `undefined`.
 * Deriving the whitelist from these keys makes that impossible by construction.
 */
const BANNERS = {
  normal: 'Benign conversation. The "Try the injection attack" button will show nothing suspicious.',
  injection: 'A bystander is attempting prompt injection. Click the attack button in the UI.',
  secrets: 'PII in the transcript: emails, phone, card, API key. All should be masked.',
  slow: 'Bee never answers. Use this to watch the timeout path.',
  crash: 'Bee exits immediately. Use this to watch the error path.',
} as const;

type Scenario = keyof typeof BANNERS;

/** Derived, not written out again. See the note on BANNERS. */
const SCENARIOS = Object.keys(BANNERS) as Scenario[];

const requested = (process.argv[2] ?? 'normal') as Scenario;
if (!Object.prototype.hasOwnProperty.call(BANNERS, requested)) {
  process.stderr.write(
    `Unknown scenario "${process.argv[2] ?? ''}". Try one of: ${SCENARIOS.join(', ')}\n`,
  );
  process.exit(1);
}
// Narrowed by the guard above, so this is a `Scenario` and the lookup is typed.
const banner: string = BANNERS[requested];

/**
 * Point the Bee client at this interpreter running the fixture, but only if the
 * operator has not already chosen.
 *
 * This used to be an unconditional assignment, which quietly overwrote a real
 * `BEE_BIN` the user had exported -- and then printed a banner telling them to
 * "unset BEE_BIN" to see real data. The script was destroying the very setting
 * it was telling them to restore. Respecting an existing value means a judge
 * with the real CLI configured gets their real data, and the fixture is only a
 * fallback for the case this script exists to cover.
 */
if (process.env.BEE_BIN === undefined || process.env.BEE_BIN === '') {
  process.env.BEE_BIN = process.execPath;
}
process.env.FAKE_BEE_SCENARIO = requested;

// The client spawns `<binary> mcp serve`, and Node resolves that leading `mcp`
// against the working directory -- which is why the chdir below is load-bearing
// rather than cosmetic. See tests/fixtures/mcp for the full explanation.
try {
  process.chdir(FIXTURES);
} catch (error) {
  // A judge who has not installed dependencies should be told what to do, not
  // shown a raw ENOENT stack trace for a path they have never heard of.
  process.stderr.write(
    `Cannot use the Bee fixtures at ${FIXTURES}.\n` +
      `  ${String(error)}\n` +
      '  Run `npm install` in bee-bridge/ first; the fixtures ship with the repo ' +
      'and are not generated.\n',
  );
  process.exit(1);
}

// The top-level await import of the server can throw for the same reason, and a
// config error from it (a short BEE_BRIDGE_TOKEN, a bad port) deserves its own
// message rather than a stack trace.
let start: () => unknown;
try {
  ({ start } = await import('../src/bee-bridge.js'));
} catch (error) {
  process.stderr.write(
    `Could not load the Bee Bridge server.\n` +
      `  ${error instanceof Error ? error.message : String(error)}\n` +
      '  Run `npm install` in bee-bridge/ and check BEE_BRIDGE_PORT and ' +
      'BEE_BRIDGE_TOKEN if you have set them.\n',
  );
  process.exit(1);
}

const usingRealBee = process.env.BEE_BIN !== process.execPath;

process.stdout.write(
  [
    '',
    `  Demo scenario: ${requested}`,
    `  ${banner}`,
    usingRealBee
      ? '  Using the BEE_BIN you set. This may be real wearable data.'
      : '  This is FIXTURE DATA, not a real wearable. To use real data, install ' +
        '@beeai/cli, run "bee login", enable Developer Mode, and unset BEE_BIN.',
    '',
  ].join('\n'),
);

start();
