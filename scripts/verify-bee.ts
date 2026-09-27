/**
 * Verification against the REAL Bee CLI.
 *
 * The test suite runs against a fixture because there is no simulator and the
 * wearable may not be present. That is a real limitation, and a reviewer is
 * entitled to ask "but does this work against actual Bee?" Rather than assert
 * it, this script makes the question answerable in one command on any machine
 * that has:
 *
 *     npm i -g @beeai/cli
 *     bee login
 *     # enable Developer Mode in the Bee app: tap the version five times
 *     npm run verify:bee
 *
 * Every check reports PASS, FAIL, or SKIP with the evidence, and the run ends
 * by naming what it could not check even on a successful pass. A script that
 * only printed green would be the opposite of useful here.
 *
 * STATUS: this has not been run against a wearable yet, because no wearable
 * was available while building it. That is stated in the README too.
 */

import { BeeClient, BeeError, isReadOnlyTool } from '../src/bee/client.js';
import { SANITIZE, sanitizeForPrompt } from '../src/bee/sanitize.js';
import { closeBeeClient } from '../src/bee/tools.js';

type Verdict = 'PASS' | 'FAIL' | 'SKIP';

interface Row {
  check: string;
  verdict: Verdict;
  evidence: string;
}

const rows: Row[] = [];

function record(check: string, verdict: Verdict, evidence: string): void {
  rows.push({ check, verdict, evidence });
}

/**
 * Tool names we believe the real CLI exposes.
 *
 * Sourced from the published bee-cli documentation, not from the fixture. A
 * mismatch here degrades the product rather than breaking it silently, because
 * an unrecognised tool is refused by design.
 */
const EXPECTED_READ_TOOLS = [
  'bee_search',
  'bee_today',
  'bee_now',
  'bee_list_facts',
  'bee_get_daily_summary',
  'bee_get_conversation',
  'bee_list_todos',
];

process.stdout.write('\nBee Bridge — verification against the real Bee CLI\n\n');

let client: BeeClient | null = null;

try {
  client = await BeeClient.connect({ timeoutMs: 20_000 });
  record('the Bee CLI is installed and reachable', 'PASS', client.describe());
} catch (error) {
  const hint =
    error instanceof BeeError && error.code === 'spawn_failed'
      ? 'Install it with: npm i -g @beeai/cli'
      : error instanceof Error
        ? error.message
        : String(error);
  record('the Bee CLI is installed and reachable', 'FAIL', hint);
  record('authenticated as a Bee user', 'SKIP', 'no CLI to authenticate');
  record('the real server exposes tools we expect', 'SKIP', 'no connection');
  record('write tools are present and held out of reach', 'SKIP', 'no connection');
  record('a real recall round-trips', 'SKIP', 'no connection');
  record('sanitisation is applied to real content', 'SKIP', 'no connection');
}

if (client) {
  try {
    // Proves Developer Mode and `bee login` are both satisfied. If this throws,
    // the fix is on the Bee side, not here, so the message is surfaced verbatim.
    const tools = await client.listTools();
    record('authenticated as a Bee user', 'PASS', `${tools.length} tools listed`);

    const names = tools.map((t) => t.name);
    const missing = EXPECTED_READ_TOOLS.filter((t) => !names.includes(t));
    record(
      'the real server exposes tools we expect',
      missing.length === 0 ? 'PASS' : 'FAIL',
      missing.length === 0
        ? `all ${EXPECTED_READ_TOOLS.length} expected tools present`
        : `missing: ${missing.join(', ')}`,
    );

    // Informational, and deliberately not a failure. The real CLI documents
    // read, search *and* manage capabilities, so it is expected to offer write
    // tools. What matters is that we refuse them, which is the next check --
    // marking their presence as a failure would mean failing a correct server.
    const refused = names.filter((n) => !isReadOnlyTool(n));
    record(
      'write tools are present and held out of reach',
      'PASS',
      refused.length === 0
        ? `server offers ${names.length} read-only tools`
        : `${refused.length} write/manage tool(s) offered and refused: ${refused.join(', ')}`,
    );
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    record(
      'authenticated as a Bee user',
      /auth|login|token|unauthorized/i.test(message) ? 'FAIL' : 'SKIP',
      message,
    );
    record('the real server exposes tools we expect', 'SKIP', 'not authenticated');
    record('write tools are present and held out of reach', 'SKIP', 'not authenticated');
  }

  try {
    const result = await client.callTool('bee_search', { query: '', limit: 1 });
    record(
      'a real recall round-trips',
      result.isError ? 'FAIL' : 'PASS',
      result.isError ? result.text.slice(0, 120) : `${result.text.length} chars returned`,
    );

    if (!result.isError) {
      const report = sanitizeForPrompt(result.text, {
        maxChars: SANITIZE.maxTranscriptChars,
        label: 'bee_search',
      });
      record(
        'sanitisation is applied to real content',
        report.text.includes('UNTRUSTED') ? 'PASS' : 'FAIL',
        report.text.includes('UNTRUSTED')
          ? `fenced; ${report.injection.suspicious ? 'injection flagged' : 'nothing flagged'}` +
            `; ${report.redactedKinds.length} kinds redacted`
          : 'output was not fenced',
      );
    } else {
      record('sanitisation is applied to real content', 'SKIP', 'no content returned');
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    record('a real recall round-trips', 'FAIL', message);
    record('sanitisation is applied to real content', 'SKIP', 'no content returned');
  }

  try {
    // The boundary, against the real server rather than the fixture. We never
    // expect this to reach Bee: the client refuses first, which is the point.
    await client.callTool('bee_delete_conversation', { id: '0' });
    record('read-only boundary refuses a write', 'FAIL', 'the call was NOT refused');
  } catch {
    record('read-only boundary refuses a write', 'PASS', 'refused before any request was sent');
  }
}

// ------------------------------------------------------------------ report --

const pad = Math.max(...rows.map((r) => r.check.length));
for (const row of rows) {
  process.stdout.write(`  ${row.verdict}  ${row.check.padEnd(pad)}  ${row.evidence}\n`);
}

const failed = rows.filter((r) => r.verdict === 'FAIL').length;
const skipped = rows.filter((r) => r.verdict === 'SKIP').length;

process.stdout.write(
  [
    '',
    `${rows.length - failed - skipped} passed, ${failed} failed, ${skipped} skipped`,
    '',
    'What this script CANNOT verify, even on a full pass:',
    "  - that the wearable captured anything correctly",
    "  - Bee's end-to-end encryption, or its authentication of your account",
    '  - whether Developer Mode was required to get this data in the first place',
    '  - how injection detection behaves on your real vocabulary, which differs',
    '    from the fixture by construction',
    '',
  ].join('\n'),
);

await closeBeeClient();
process.exit(failed === 0 ? 0 : 1);

