/**
 * One-command demo against the fixture `bee`, for when there is no hardware.
 *
 * The real track needs the wearable, the app, and Developer Mode. This exists
 * so a judge, a reviewer, or you on a train can still see the whole trust
 * boundary working end to end.
 *
 *     npm run demo              # benign conversation
 *     npm run demo -- attack    # the injection scenario
 *     npm run demo -- secrets   # the redaction scenario
 *
 * The scenario has to be set in-process, before the server module loads, for
 * the same reason the smoke tests set it there: the setting is read by the
 * fixture process at startup, so exporting it in the surrounding shell is not
 * enough to be sure it arrives.
 */

import { fileURLToPath } from 'node:url';

const FIXTURES = fileURLToPath(new URL('../tests/fixtures/', import.meta.url));

const requested = process.argv[2] ?? 'normal';
const SCENARIOS = new Set(['normal', 'injection', 'secrets', 'slow', 'crash']);
if (!SCENARIOS.has(requested)) {
  process.stderr.write(
    `Unknown scenario "${requested}". Try one of: ${[...SCENARIOS].join(', ')}\n`,
  );
  process.exit(1);
}

// Point the Bee client at this interpreter running the fixture. The client
// spawns `<binary> mcp serve`, and Node resolves that leading `mcp` against the
// working directory -- which is why the chdir below is load-bearing rather than
// cosmetic. See tests/fixtures/mcp for the full explanation.
process.env.BEE_BIN = process.execPath;
process.env.FAKE_BEE_SCENARIO = requested;
process.chdir(FIXTURES);

const { start } = await import('../src/bee-bridge.js');

const banner = {
  normal: 'Benign conversation. The "Try the injection attack" button will show nothing suspicious.',
  injection: 'A bystander is attempting prompt injection. Click the attack button in the UI.',
  secrets: 'PII in the transcript: emails, phone, card, API key. All should be masked.',
  slow: 'Bee never answers. Use this to watch the timeout path.',
  crash: 'Bee exits immediately. Use this to watch the error path.',
}[requested];

process.stdout.write(
  [
    '',
    `  Demo scenario: ${requested}`,
    `  ${banner}`,
    `  This is FIXTURE DATA, not a real wearable. To use real data, install`,
    `  @beeai/cli, run "bee login", enable Developer Mode, and unset BEE_BIN.`,
    '',
  ].join('\n'),
);

start();
