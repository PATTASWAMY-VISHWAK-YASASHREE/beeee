/**
 * Is the bridge talking to real Bee, or to a stand-in?
 *
 * This exists because of a specific failure mode found in an audit: with the
 * test fixture wired up, `/health` returned `ok: true` and the `bee_status`
 * tool said *"Bee is reachable"*. Both were untrue. Nothing on any surface
 * indicated that the transcripts were fabricated, which is precisely the
 * situation where a demo quietly misleads someone who has no way to tell.
 *
 * A project whose whole argument is that the trust boundary has to be honest
 * cannot ship a status endpoint that lies about where the data came from.
 */

/** The real CLI is expected on PATH under this name. */
const REAL_BIN = 'bee';

export interface BeeMode {
  /** True when the bridge is reading fabricated or stand-in content. */
  standIn: boolean;
  /** Short machine-readable label: "bee" or "stand-in". */
  source: 'bee' | 'stand-in';
  /** Why we think so, for a human reading a status response. */
  reason: string;
  /** Sentence to surface to a user or a judge. Empty when talking to real Bee. */
  notice: string;
}

export function detectBeeMode(
  binary: string,
  env: NodeJS.ProcessEnv = process.env,
): BeeMode {
  // An explicit override wins, so an operator can flag a stand-in that happens
  // to be invoked as `bee` on PATH.
  const forced = env.SPRIG_BEE_STANDIN?.trim().toLowerCase();
  if (forced === '1' || forced === 'true' || forced === 'yes') {
    return {
      standIn: true,
      source: 'stand-in',
      reason: 'SPRIG_BEE_STANDIN is set',
      notice:
        'STAND-IN MODE: this bridge is not reading Amazon Bee. It is reading fabricated or ' +
        'stand-in content. Do not present this data as a Bee integration.',
    };
  }

  // `FAKE_BEE_SCENARIO` is set only by our own test fixture, so its presence
  // is a reliable signal that whatever `bee` resolves to is not the product.
  if (env.FAKE_BEE_SCENARIO) {
    return {
      standIn: true,
      source: 'stand-in',
      reason: `FAKE_BEE_SCENARIO is set (${env.FAKE_BEE_SCENARIO})`,
      notice:
        'STAND-IN MODE: this bridge is not reading Amazon Bee. It is reading fabricated ' +
        'content from a test fixture. Do not present this data as a Bee integration.',
    };
  }

  // A binary that is not literally `bee` is not the product CLI. Pointing
  // BEE_BIN at an interpreter to run a fake is the common way this happens.
  if (binary !== REAL_BIN) {
    return {
      standIn: true,
      source: 'stand-in',
      reason: `BEE_BIN is "${binary}", not the real "bee" CLI`,
      notice:
        `STAND-IN MODE: the Bee binary is "${binary}", not "bee". This bridge is not ` +
        'reading Amazon Bee, and the content it returns should not be presented as a real ' +
        'Bee integration.',
    };
  }

  return { standIn: false, source: 'bee', reason: 'BEE_BIN is the real bee CLI', notice: '' };
}
