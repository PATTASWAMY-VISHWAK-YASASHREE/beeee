import { describe, expect, it } from 'vitest';

import { detectBeeMode } from '../src/bee/mode.js';

/**
 * Tests for stand-in disclosure.
 *
 * The bug these guard against was found by auditing the running server, not by
 * reading it: with the test fixture wired up, `/health` returned `ok: true` and
 * `bee_status` said "Bee is reachable". Both untrue, and nothing said so. A
 * demo that quietly serves fabricated data is the one failure mode this
 * project cannot afford, because its entire argument is about being honest
 * about where data comes from.
 */

describe('detectBeeMode', () => {
  it('reports the real CLI as real', () => {
    const mode = detectBeeMode('bee', {});
    expect(mode.standIn).toBe(false);
    expect(mode.source).toBe('bee');
    // No notice when there is nothing to warn about.
    expect(mode.notice).toBe('');
  });

  it('flags a binary that is not the real CLI', () => {
    const mode = detectBeeMode('C:\\Program Files\\nodejs\\node.exe', {});
    expect(mode.standIn).toBe(true);
    expect(mode.source).toBe('stand-in');
    expect(mode.notice).toMatch(/not reading Amazon Bee/i);
  });

  it('flags the test fixture via its scenario marker', () => {
    // This is the exact configuration the audit caught: BEE_BIN pointed at
    // node to run the fixture, with a scenario set.
    const mode = detectBeeMode('bee', { FAKE_BEE_SCENARIO: 'injection' });
    expect(mode.standIn).toBe(true);
    expect(mode.reason).toMatch(/FAKE_BEE_SCENARIO/);
  });

  it('flags the fixture even when the binary looks like bee', () => {
    // Belt and braces: the marker is checked independently of the binary name,
    // so a stand-in invoked as `bee` on PATH is still caught.
    const mode = detectBeeMode('bee', { FAKE_BEE_SCENARIO: 'normal' });
    expect(mode.standIn).toBe(true);
  });

  it('honours an explicit override in either direction', () => {
    expect(detectBeeMode('bee', { SPRIG_BEE_STANDIN: '1' }).standIn).toBe(true);
    expect(detectBeeMode('bee', { SPRIG_BEE_STANDIN: 'true' }).standIn).toBe(true);
    // The override is one-way on purpose: a stray "0" must not be able to
    // silence a real stand-in.
    expect(detectBeeMode('bee', { SPRIG_BEE_STANDIN: '0' }).standIn).toBe(false);
  });

  it('tolerates whitespace in the override, as cmd likes to add it', () => {
    // `set SPRIG_BEE_STANDIN=1 && next` yields "1 ". If this were not trimmed
    // the override would silently do nothing.
    expect(detectBeeMode('bee', { SPRIG_BEE_STANDIN: ' 1 ' }).standIn).toBe(true);
  });

  it('always gives a non-empty reason', () => {
    expect(detectBeeMode('bee', {}).reason.length).toBeGreaterThan(0);
    expect(detectBeeMode('/usr/bin/node', {}).reason.length).toBeGreaterThan(0);
  });

  it('never leaves an empty notice while standing in', () => {
    // A stand-in that reports itself with a blank notice is the same bug in a
    // smaller hat.
    for (const [bin, env] of [
      ['node', {}],
      ['bee', { FAKE_BEE_SCENARIO: 'x' }],
      ['bee', { SPRIG_BEE_STANDIN: 'yes' }],
    ] as const) {
      const mode = detectBeeMode(bin, env);
      if (mode.standIn) expect(mode.notice.length).toBeGreaterThan(10);
    }
  });

  it('believes a server that says it is a stand-in', () => {
    // Found by running the bridge against Wristbox over the HTTP transport
    // with BEE_BIN unset: it reported `dataSource: "bee"` and said "Bee is
    // reachable" while reading stand-in content. The endpoint can point
    // anywhere, so the handshake is the only reliable evidence.
    const mode = detectBeeMode('bee', {}, 'wristbox');
    expect(mode.standIn).toBe(true);
    expect(mode.reason).toMatch(/wristbox/);
    expect(mode.notice).toMatch(/not Amazon Bee/i);
  });

  it('trusts the handshake over a clean environment', () => {
    // Self-identification wins even when every env signal looks fine.
    expect(detectBeeMode('bee', {}, 'fake-bee').standIn).toBe(true);
  });

  it('does not invent a stand-in from an unfamiliar server name', () => {
    // The real CLI's serverInfo name is unknown to us, so an unrecognised name
    // is not evidence. Treating it as one would cry wolf against the real
    // product, which trains people to ignore the warning.
    expect(detectBeeMode('bee', {}, 'some-unexpected-name').standIn).toBe(false);
  });

  it('treats a null or absent server name as no information', () => {
    expect(detectBeeMode('bee', {}, null).standIn).toBe(false);
    expect(detectBeeMode('bee', {}).standIn).toBe(false);
  });
});
