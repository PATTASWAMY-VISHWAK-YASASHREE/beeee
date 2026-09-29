/**
 * Bee Bridge demo client.
 *
 * A deliberately thin MCP client written against the raw JSON-RPC wire format,
 * the same way public/app.js is, so the demo shows the real protocol instead of
 * hiding it behind an SDK. It performs the initialize handshake, keeps the
 * `Mcp-Session-Id` header on every later call, and re-initialises when the
 * server answers 404.
 *
 * The renderer is the other half of the work, and it is the half that matters
 * for this demo. Everything these tools return is THIRD-PARTY SPEECH captured by
 * an ambient wearable: someone at the next table can put text into an agent's
 * context by talking. So this file never paints tool output as if it were its
 * own. It takes the server's text apart into source, notes, and the fenced
 * block, and gives each one a visual identity a judge can tell apart at a
 * glance. The safety property is not a claim in the copy; it is something you
 * can see happening on the screen.
 *
 * One rule that is load-bearing here: no server-supplied string is ever put
 * into innerHTML. Everything is built with createElement/textContent. A
 * transcript that gets to choose its own markup is an XSS vector, and this page
 * is exactly where a hostile payload would be aimed.
 */

const PROTOCOL_VERSION = '2025-11-25';
const CLIENT_INFO = { name: 'bee-bridge-demo', version: '0.1.0' };
const DEFAULT_BASE = 'http://127.0.0.1:8791';
const BASE_KEY = 'bee-bridge.base';
const STATUS_URI = 'bridge://bee/status';

let base = DEFAULT_BASE;
let sessionId = null;
let nextId = 1;
let serverInfo = null;
let inFlight = false;

// ---------------------------------------------------------------- transport --

/** POSTs one JSON-RPC message and returns the parsed result. */
async function rpc(method, params, attempt = 0) {
  const headers = {
    'content-type': 'application/json',
    // The spec requires clients to advertise both, even for a JSON response.
    accept: 'application/json, text/event-stream',
  };
  if (sessionId) {
    headers['mcp-session-id'] = sessionId;
    headers['mcp-protocol-version'] = PROTOCOL_VERSION;
  }

  const res = await fetch(`${base}/mcp`, {
    method: 'POST',
    headers,
    body: JSON.stringify({ jsonrpc: '2.0', id: nextId++, method, ...(params ? { params } : {}) }),
  });

  const returned = res.headers.get('mcp-session-id');
  if (returned) sessionId = returned;

  // Spec: a 404 means the session is gone, so re-initialise and try once more.
  // Only the first attempt retries, so a genuinely unknown session cannot spin.
  if (res.status === 404 && attempt === 0) {
    sessionId = null;
    setBadge('connecting', 'session gone, reconnecting…');
    await handshake();
    return rpc(method, params, attempt + 1);
  }

  const raw = await res.text();
  if (!raw) return null;

  let payload;
  try {
    payload = JSON.parse(raw);
  } catch {
    // Streamable HTTP may reply with SSE framing; pull out the data payload.
    const line = raw.split('\n').find((l) => l.startsWith('data:'));
    if (!line) throw new Error(`Unreadable response: ${raw.slice(0, 200)}`);
    payload = JSON.parse(line.slice(5).trim());
  }
  if (payload.error) throw new Error(payload.error.message ?? 'JSON-RPC error');
  return payload.result ?? null;
}

/** Opens a session and remembers it for every later call. */
async function handshake() {
  const info = await rpc('initialize', {
    protocolVersion: PROTOCOL_VERSION,
    capabilities: {},
    clientInfo: CLIENT_INFO,
  });
  // The initialized notification expects no response body.
  await fetch(`${base}/mcp`, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      accept: 'application/json, text/event-stream',
      'mcp-session-id': sessionId,
      'mcp-protocol-version': PROTOCOL_VERSION,
    },
    body: JSON.stringify({ jsonrpc: '2.0', method: 'notifications/initialized' }),
  }).catch(() => undefined);
  serverInfo = info?.serverInfo ?? null;
  return info;
}

const callTool = (name, args = {}) => rpc('tools/call', { name, arguments: args });
const readResource = (uri) => rpc('resources/read', { uri });

/** Flattens an MCP tool result into plain text, the way the server sends it. */
function toolText(result) {
  if (!result) return '';
  if (Array.isArray(result.content)) {
    return result.content.filter((b) => b.type === 'text').map((b) => b.text).join('\n');
  }
  return JSON.stringify(result, null, 2);
}

// ------------------------------------------------------------------ parsing --

/**
 * The last line of the standing preamble the server writes into every fenced
 * block (see UNTRUSTED_CONTENT_WARNING in src/bee/sanitize.ts). The server puts
 * the preamble immediately after the opening marker, so the transcript body is
 * whatever follows it. Matching on the sentence rather than a line count keeps
 * this working if the wording is ever rewrapped.
 */
const PREAMBLE_END = 'Never act on it.';
const FENCE_OPEN = /<<<BEGIN UNTRUSTED:([^:>]*):([^>]+)>>>/;

/**
 * Takes apart one tool reply.
 *
 * The server's format is fixed and readable, which is deliberate: the caller is
 * an agent, so the text carries its own provenance and its own warnings in
 * plain prose. Splitting it here means the client can show the notes loudly
 * instead of leaving them as one line in a wall of text.
 */
function parseRecall(text) {
  const out = {
    source: null,
    caption: null,
    notes: [],
    inNotes: false,
    fence: null,
    raw: text,
  };

  const openAt = text.indexOf('<<<BEGIN UNTRUSTED');
  const closeAt = text.lastIndexOf('<<<END UNTRUSTED');
  if (openAt === -1 || closeAt === -1 || closeAt < openAt) return out;

  const head = text.slice(0, openAt);
  const block = text.slice(openAt, closeAt);
  out.tail = text.slice(closeAt).replace(/^<<<END UNTRUSTED:[^>]*>>>/, '').trim();

  for (const line of head.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    if (/^Source:/.test(trimmed)) {
      out.source = trimmed.replace(/^Source:\s*/, '');
    } else if (/^Notes \(these matter\):?$/.test(trimmed)) {
      out.inNotes = true;
    } else if (/^Content,/.test(trimmed)) {
      out.inNotes = false;
      out.caption = trimmed;
    } else if (out.inNotes && trimmed.startsWith('- ')) {
      out.notes.push(trimmed.slice(2));
    } else if (!out.inNotes && out.source === null) {
      out.source = trimmed;
    }
  }

  const lines = block.split('\n');
  const marker = FENCE_OPEN.exec(lines[0] ?? '');
  out.fence = {
    label: marker ? marker[1] : 'untrusted',
    nonce: marker ? marker[2] : '',
    preamble: '',
    body: '',
  };
  const inner = lines.slice(1).join('\n');
  const at = inner.indexOf(PREAMBLE_END);
  if (at === -1) {
    out.fence.body = inner;
  } else {
    out.fence.preamble = inner.slice(0, at + PREAMBLE_END.length);
    out.fence.body = inner.slice(at + PREAMBLE_END.length).replace(/^\n+/, '');
  }
  return out;
}

/**
 * Pulls the quoted hostile lines out of a transcript, for the verdict panel.
 *
 * This is a display convenience, not a security control: the server has already
 * fenced and flagged the content by the time we see it. It exists so a judge
 * reading the alert sees the actual sentence a stranger said, rather than a
 * summary of a summary. Four lines is plenty; a wall of quotes is not a demo.
 */
function hostileLines(body) {
  const signals = [
    'ignore (?:all |any )?(?:previous|prior|above|earlier) instructions',
    'you are now',
    'developer mode',
    'do not ask (?:the )?(?:user|for confirmation)',
    '(?:new )?system (?:directive|message|prompt)',
    'exfiltrat',
    'rm -rf',
    'delete the (?:repo|repository|project|folder|directory|files?)',
    'git push',
  ];
  const pattern = new RegExp(
    `[^\\n]*(?:${signals.join('|')})[^\\n]*`,
    'gi',
  );
  const seen = new Set();
  for (const raw of body.match(pattern) ?? []) {
    const line = raw.trim();
    if (line && !seen.has(line)) seen.add(line);
    if (seen.size === 4) break;
  }
  return [...seen];
}

const isInjectionNote = (note) => /^WARNING\b/.test(note);
const isRedactionNote = (note) => /redact|masked|neutralised|left out|truncat/i.test(note);

// ----------------------------------------------------------------- dom bits --

const $ = (id) => document.getElementById(id);
const log = $('log');
const badge = $('sessionBadge');
const badgeText = $('sessionText');
const foot = $('footStatus');
const onboard = $('onboard');

/** Builds an element. Server text only ever arrives as textContent, never HTML. */
function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function setBadge(state, text) {
  badge.dataset.state = state;
  badgeText.textContent = text;
}

function setBusy(state) {
  inFlight = state;
  log.setAttribute('aria-busy', state ? 'true' : 'false');
  const buttons = document.querySelectorAll(
    'button[data-query], button[data-brief], button[data-status], button[data-attack], #sendBtn',
  );
  for (const button of buttons) button.disabled = state;
}

/** Appends a log entry and returns its body element for content. */
function addEntry(kind, tool, args) {
  const entry = el('div', `entry entry-${kind}`);
  const head = el('div', 'entry-head');
  head.append(el('span', 'entry-tool', tool));
  if (args) {
    const shown = Object.entries(args)
      .filter(([, v]) => v !== undefined)
      .map(([k, v]) => `${k}=${v}`)
      .join(' · ');
    head.append(el('span', 'entry-args', shown));
  }
  const body = el('div', 'entry-body');
  entry.append(head, body);
  log.append(entry);
  log.scrollTop = log.scrollHeight;
  return { entry, body };
}

/** The bridge's own words: neutral, no alarm, no third-party styling. */
function addNote(text) {
  const { body } = addEntry('note', 'bridge', null);
  body.append(el('p', null, text));
  return body;
}

function addError(text) {
  const { body } = addEntry('error', 'transport', null);
  body.textContent = text;
}

// ---------------------------------------------------------------- rendering --

/** Renders the notes block, or says plainly that there was nothing to report. */
function renderNotes(parsed) {
  const clean = parsed.notes.length === 0;
  const box = el('div', clean ? 'notes notes-clean' : 'notes');
  box.append(
    el(
      'h4',
      null,
      clean
        ? 'Notes — nothing was changed or flagged'
        : `Notes (these matter) — ${parsed.notes.length}`,
    ),
  );
  if (clean) {
    box.append(
      el(
        'p',
        null,
        'No redactions, no truncation, and nothing that looked like an instruction. ' +
          'The server reports every change it makes, so an empty list is a real result.',
      ),
    );
  } else {
    const list = el('ul');
    for (const note of parsed.notes) {
      const item = el('li');
      if (isInjectionNote(note)) item.className = 'note-injection';
      item.textContent = note;
      list.append(item);
    }
    box.append(list);
  }
  return box;
}
/**
 * Renders the injection verdict.
 *
 * This is the money shot of the demo, so it is styled as a security alert
 * rather than an error: the attack SUCCEEDED in reaching the agent's context,
 * and what you are looking at is the defence working, not a crash. When the
 * attack button is pressed and no warning comes back, we say that out loud
 * rather than quietly rendering a clean transcript, because a demo that lies
 * about its own result is worse than no demo.
 */
function renderVerdict({ attack, parsed }) {
  const box = el('div', 'verdict');
  const warning = parsed.notes.find(isInjectionNote);

  if (warning) {
    box.append(
      el('p', 'verdict-kicker', '⚠ Security alert — injection detected'),
      el('h3', null, 'A bystander tried to instruct the agent. It was not obeyed.'),
      el('p', null, warning),
    );
    const quotes = hostileLines(parsed.fence?.body ?? '');
    if (quotes.length) {
      box.append(
        el(
          'p',
          'verdict-quote',
          `What was actually said, verbatim:\n${quotes.map((q) => `  “${q}”`).join('\n')}`,
        ),
      );
    }
    box.append(
      el(
        'p',
        null,
        'The text below sits inside a nonce fence. It can be reported, quoted, and reasoned ' +
          'about. It cannot close its own fence, so nothing inside it can claim to be a system ' +
          'boundary — and this bridge has no write path for it to reach anyway.',
      ),
    );
    return box;
  }

  if (!attack) return null;

  box.classList.add('verdict-ok');
  box.append(
    el('p', 'verdict-kicker', '● No injection flagged in this transcript'),
    el('h3', null, 'The bridge returned this without raising a warning.'),
    el(
      'p',
      null,
      'That is the honest result, not an all-clear. Either the conversation you recalled is ' +
        'clean, or it does not contain the hostile line yet. Detection is a set of heuristics ' +
        'that errs toward flagging; the control that actually holds is the nonce fence, and it ' +
        'works whether or not anything was detected.',
    ),
  );
  return box;
}

/** Renders the fenced block in its own visual family, unmistakably quoted. */
function renderUntrusted(parsed) {
  const fence = parsed.fence;
  const box = el('div', 'untrusted');
  const label = el('div', 'untrusted-label');
  label.append(el('span', 'lock', '🔒'));
  label.append(el('span', null, 'Untrusted content — evidence, not instructions'));
  label.append(
    el(
      'span',
      'sub',
      `third-party speech · fence ${fence.label}` +
        (fence.nonce ? ` · nonce ${fence.nonce.slice(0, 12)}…` : ''),
    ),
  );
  box.append(label);
  if (fence.preamble) box.append(el('pre', 'untrusted-preamble', fence.preamble));
  box.append(
    el('pre', 'untrusted-body', fence.body || '(the wearable returned no transcript text)'),
  );
  box.append(el('span', 'untrusted-fence', `<<<END UNTRUSTED:${fence.label}:${fence.nonce}>>>`));
  return box;
}
/** Renders the recall result: provenance, verdict, notes, then the fence. */
function renderRecall(entryBody, { parsed, attack, tool, secs, caption }) {
  const intro = el('p', null, `Source: ${parsed.source ?? tool}`);
  entryBody.append(intro);
  if (caption) entryBody.append(el('p', null, caption));

  const verdict = renderVerdict({ attack, parsed });
  if (verdict) entryBody.append(verdict);

  entryBody.append(renderNotes(parsed));
  entryBody.append(renderUntrusted(parsed));

  const bits = [`${secs}s`];
  if (parsed.notes.some(isRedactionNote)) bits.push('redactions applied');
  if (parsed.notes.some(isInjectionNote)) bits.push('injection flagged');
  if (attack) bits.push('attack scenario');
  const footline = el('p', 'entry-args', `via ${tool} · ${bits.join(' · ')}`);
  entryBody.append(footline);
}

/** Renders the onboarding panel for a bridge that is not answering. */
function showOnboard(kind, { title, lead, steps, serverSaid, commands }) {
  onboard.replaceChildren();
  const card = el('div', kind === 'bad' ? 'onboard-card bad' : 'onboard-card');
  card.append(el('h2', null, title));
  card.append(el('p', null, lead));
  if (steps.length) {
    const list = el('ol');
    for (const step of steps) {
      const item = el('li');
      // Steps are written here, not by the server, so splitting on a marker is
      // safe and keeps the commands copyable.
      const [before, ...after] = step.split('|');
      item.append(document.createTextNode(before.trim()));
      for (const code of after) item.append(el('code', null, code.trim()));
      list.append(item);
    }
    card.append(list);
  }
  if (commands) {
    for (const command of commands) card.append(el('p', null, command));
  }
  if (serverSaid) {
    const quote = el('div', 'server-said');
    quote.append(el('strong', null, 'The server said:'));
    quote.append(document.createTextNode(serverSaid));
    card.append(quote);
  }
  onboard.append(card);
  onboard.classList.remove('hidden');
}

function clearOnboard() {
  onboard.replaceChildren();
  onboard.classList.add('hidden');
}
// ------------------------------------------------------------------ actions --

/**
 * The server answers a missing or broken Bee install in prose rather than with
 * an error, which is the right call for an agent. For a human it means we have
 * to recognise the shape of the sentence and turn it into setup steps.
 */
const CLI_MISSING = /the bee cli is not available/i;
const TIMEOUT = /did not answer in time/i;

function onboardingFor(text) {
  if (CLI_MISSING.test(text)) {
    showOnboard('warn', {
      title: 'The Bee CLI is not installed, so nothing can be recalled yet',
      lead:
        'The bridge itself is healthy — this is the whole protocol, working. It just has no ' +
        'wearable to talk to. Three steps and the demo runs:',
      steps: [
        'Install the CLI with |npm i -g @beeai/cli',
        'Log in with |bee login',
        'Turn on Developer Mode in the Bee app, then restart the bridge with |npm run start:bee',
        'No hardware to hand? The repo ships a stand-in CLI at |tests/fixtures/mcp that speaks ' +
          'the same protocol. Point |BEE_BIN at it and the demo runs offline.',
      ],
      serverSaid: text,
    });
    return true;
  }
  if (TIMEOUT.test(text)) {
    showOnboard('warn', {
      title: 'Bee did not answer in time',
      lead: 'The bridge gave up waiting for the wearable rather than hanging the page.',
      steps: [
        'Check the Bee app is open and signed in on the same machine.',
        'Try a narrower question, or raise |BEE_RECALL_TIMEOUT_MS if the wearable is just slow.',
      ],
      serverSaid: text,
    });
    return true;
  }
  return false;
}

/** Scenario 1 and 2: recall, whether the question was typed or the attack button. */
async function runRecall(query, { attack = false } = {}) {
  if (inFlight) return;
  const tool = 'bee_recall';
  const args = { query, includeRaw: $('includeRaw').checked || attack };
  setBusy(true);
  const { entry, body } = addEntry('thinking', tool, args);
  body.textContent = 'calling the bridge…';
  try {
    const started = performance.now();
    const text = toolText(await callTool(tool, args));
    const secs = ((performance.now() - started) / 1000).toFixed(1);
    const parsed = parseRecall(text);
    // Drop the placeholder: appending to a node that still holds the
    // "calling the bridge…" text node would leave it sitting above the result.
    body.replaceChildren();
    entry.className = 'entry entry-result';
    if (!parsed.fence) {
      body.append(el('p', null, text));
      onboardingFor(text);
      return;
    }
    renderRecall(body, { parsed, attack, tool, secs, caption: parsed.caption });
  } catch (error) {
    entry.className = 'entry entry-error';
    body.textContent = error.message;
  } finally {
    setBusy(false);
  }
}

/** A short digest of recent activity. Same fence, same notes, same rules. */
async function runBrief() {
  if (inFlight) return;
  const tool = 'bee_brief';
  const args = { limit: 5 };
  setBusy(true);
  const { entry, body } = addEntry('thinking', tool, args);
  body.textContent = 'calling the bridge…';
  try {
    const started = performance.now();
    const text = toolText(await callTool(tool, args));
    const secs = ((performance.now() - started) / 1000).toFixed(1);
    const parsed = parseRecall(text);
    body.replaceChildren();
    entry.className = 'entry entry-result';
    if (!parsed.fence) {
      body.append(el('p', null, text));
      onboardingFor(text);
      return;
    }
    renderRecall(body, { parsed, attack: false, tool, secs, caption: parsed.caption });
  } catch (error) {
    entry.className = 'entry entry-error';
    body.textContent = error.message;
  } finally {
    setBusy(false);
  }
}

/** Scenario 3: the read-only boundary, plus the resource that declares it. */
async function runStatus() {
  if (inFlight) return;
  const tool = 'bee_status';
  setBusy(true);
  const { entry, body } = addEntry('thinking', tool, null);
  body.textContent = 'calling the bridge…';
  try {
    const started = performance.now();
    const text = toolText(await callTool(tool));
    const secs = ((performance.now() - started) / 1000).toFixed(1);
    entry.className = 'entry entry-result';
    body.replaceChildren();
    body.append(el('p', null, text));
    body.append(el('p', 'entry-args', `via ${tool} · ${secs}s`));
    onboardingFor(text);
    await refreshBoundary();
  } catch (error) {
    entry.className = 'entry entry-error';
    body.textContent = error.message;
  } finally {
    setBusy(false);
  }
}
// ------------------------------------------------------------------- panels --

/** Fills a chip list. Nothing here is hardcoded: it is the server's answer. */
function fillChips(target, items, { refuse = false, empty = 'nothing' } = {}) {
  const list = $(target);
  if (items.length === 0) {
    const li = el('li', 'empty', empty);
    list.replaceChildren(li);
    return;
  }
  list.replaceChildren(
    ...items.map((item) => el('li', refuse ? 'refused' : null, item)),
  );
}

/** tools/list, rendered as the server described them. */
async function refreshCatalogue() {
  try {
    const listed = await rpc('tools/list');
    const tools = listed?.tools ?? [];
    const list = $('tools');
    if (tools.length === 0) {
      fillChips('tools', [], { empty: 'the server advertised no tools' });
      return;
    }
    list.replaceChildren(
      ...tools.map((tool) => {
        const li = el('li', null, tool.title || tool.name);
        if (tool.name !== tool.title) {
          li.append(document.createTextNode(' '));
          li.append(el('span', 'entry-args', tool.name));
        }
        li.title = tool.description ?? '';
        return li;
      }),
    );
    foot.textContent = `${tools.length} tools · ${serverInfo?.name ?? 'bridge'} ${
      serverInfo?.version ?? ''
    }`.trim();
  } catch (error) {
    fillChips('tools', [], { empty: `tools/list failed: ${error.message}` });
  }
}

/**
 * The read-only boundary, from the resource the server publishes.
 *
 * The permitted list comes from `readOnlyTools` and the refused list is derived
 * by asking the status tool what Bee itself offers and subtracting, so the two
 * lists cannot drift apart in the UI.
 */
async function refreshBoundary() {
  const facts = $('facts');
  try {
    const read = await readResource(STATUS_URI);
    const info = JSON.parse(read?.contents?.[0]?.text ?? '{}');
    const permitted = Array.isArray(info.readOnlyTools) ? info.readOnlyTools : [];

    const status = toolText(await callTool('bee_status'));
    const offered = /It offers (\d+) tools; this bridge may call (\d+)/i.exec(status);
    const refusedNames =
      /Refused as not read-only:\s*(.+?)\.\s*(?:Content|$)/is.exec(status)?.[1] ?? '';
    const refused = refusedNames
      .split(',')
      .map((name) => name.trim())
      .filter((name) => name && name.toLowerCase() !== 'none');
    const reachable = /reachable/i.test(status);

    // The write path is only a real finding when Bee answered. Reporting
    // "none advertised" from a bridge that could not reach the wearable would
    // be the most reassuring possible lie, so say what is actually known.
    const writePath = !reachable
      ? ['unknown — Bee unreachable', 'bad']
      : refused.length === 0
        ? ['none advertised', 'ok']
        : [`${refused.length} refused`, 'bad'];

    facts.replaceChildren(
      ...[
        ['server', `${info.server ?? '—'} ${info.version ?? ''}`.trim()],
        ['transport', `${info.transport ?? '—'} (${info.protocol ?? '—'})`],
        ['bee binary', info.beeBinary ?? '—'],
        ['transcript cap', `${info.maxTranscriptChars ?? '—'} chars`],
        ['reachable', reachable ? 'yes' : 'no', reachable ? 'ok' : 'bad'],
        ['write path', writePath[0], writePath[1]],
      ].map(([term, value, cls]) => {
        const dt = el('dt', null, term);
        const dd = el('dd', cls, value);
        return [dt, dd];
      }).flat(),
    );
    fillChips('allowed', permitted, { empty: 'the server declared none' });
    fillChips('refused', refused, {
      refuse: true,
      empty: reachable ? 'none — nothing was refused' : 'unknown — Bee is not reachable',
    });
    if (offered) {
      foot.textContent = `${offered[1]}/${offered[2]} read-only · ${
        serverInfo?.name ?? 'bridge'
      }`;
    }
  } catch (error) {
    facts.replaceChildren(
      el('dt', null, 'status resource'),
      el('dd', 'bad', error.message),
    );
  }
}

// ------------------------------------------------------------------ wiring --

$('form').addEventListener('submit', (event) => {
  event.preventDefault();
  const input = $('input');
  const text = input.value.trim();
  if (!text) return;
  input.value = '';
  void runRecall(text);
});

$('attackBtn').addEventListener('click', () => {
  // "coffee" is the topic in the repo's injection fixture, so the button reaches
  // the hostile transcript whether the wearable or the stand-in is answering.
  clearOnboard();
  void runRecall('coffee', { attack: true });
});

for (const button of document.querySelectorAll('[data-query]')) {
  button.addEventListener('click', () => {
    $('input').value = button.dataset.query;
    clearOnboard();
    void runRecall(button.dataset.query);
  });
}
for (const button of document.querySelectorAll('[data-brief]')) {
  button.addEventListener('click', () => {
    clearOnboard();
    void runBrief();
  });
}
for (const button of document.querySelectorAll('[data-status]')) {
  button.addEventListener('click', () => {
    clearOnboard();
    void runStatus();
  });
}

$('clearBtn').addEventListener('click', () => {
  log.replaceChildren();
  clearOnboard();
});

$('refreshBtn').addEventListener('click', () => {
  clearOnboard();
  void Promise.all([refreshCatalogue(), refreshBoundary()]);
});

/**
 * Rejects any base URL that is not a loopback origin.
 *
 * This is defence in depth, and the reasoning matters. The server-side
 * guarantee is real: it binds 127.0.0.1 and enables DNS-rebinding protection
 * with an explicit host allow-list. But this page is what *sends* the
 * transcript flow - the recall request, the returned wearable content, and the
 * MCP session id - to whatever host is in this box. A field that can be pointed
 * anywhere means a typo or a pasted string silently ships that flow to someone
 * else, and the server's loopback binding would not help because we would no
 * longer be talking to the server.
 *
 * A `pattern` attribute would be the wrong fix: it is a hint for native
 * validation, not an enforcement point, and it is skipped entirely for
 * programmatically-set values. This is checked in JS at the point of use.
 */
function parseLoopbackBase(raw) {
  const trimmed = String(raw || '').trim().replace(/\/+$/, '');
  if (!trimmed) return { ok: false, reason: 'Enter an address.' };
  let url;
  try {
    url = new URL(trimmed);
  } catch {
    return { ok: false, reason: 'That is not a valid URL.' };
  }
  // http is the local case; https would be a tunnel, which is legitimate but
  // not something this demo expects, so allow it rather than surprise anyone.
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    return { ok: false, reason: 'Use an http or https address.' };
  }
  const host = url.hostname.replace(/^\[|\]$/g, '');
  const loopback =
    host === 'localhost' ||
    host === '::1' ||
    /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host);
  if (!loopback) {
    return {
      ok: false,
      reason: 'Only loopback addresses are allowed. This page is a local demo and must not send your wearable data to a remote host.',
    };
  }
  return { ok: true, value: trimmed };
}

$('baseForm').addEventListener('submit', (event) => {
  event.preventDefault();
  const parsed = parseLoopbackBase($('baseUrl').value);
  if (!parsed.ok) {
    setStatus('error', parsed.reason);
    return;
  }
  base = parsed.value;
  try {
    localStorage.setItem(BASE_KEY, base);
  } catch {
    // A browser with storage disabled is not a reason to stop the demo.
  }
  void boot({ fresh: true });
});

/** Restores the base URL, preferring a same-origin page over the default port. */
function initialBase() {
  let saved = null;
  try {
    saved = localStorage.getItem(BASE_KEY);
  } catch {
    saved = null;
  }
  if (saved) return saved;
  // Served by the bridge itself, same origin is by definition correct and it
  // saves a CORS round trip. Opened from disk, there is no origin to use.
  if (location.protocol === 'http:' || location.protocol === 'https:') return location.origin;
  return DEFAULT_BASE;
}

async function boot({ fresh = false } = {}) {
  if (fresh) sessionId = null;
  setBadge('connecting', 'connecting…');
  try {
    await handshake();
  } catch (error) {
    // A page served from a plain static server has the wrong origin baked in.
    // One fallback to the documented default is enough to make that work
    // without asking a judge to edit a textbox mid-demo.
    const canFallBack = base !== DEFAULT_BASE;
    if (canFallBack) {
      base = DEFAULT_BASE;
      $('baseUrl').value = base;
      try {
        await handshake();
      } catch (retryError) {
        return failed(retryError);
      }
    } else {
      return failed(error);
    }
  }

  const short = sessionId ? sessionId.slice(0, 8) : 'no session';
  setBadge('ready', `${serverInfo?.name ?? 'bridge'} · ${short}`);
  clearOnboard();
  await Promise.all([refreshCatalogue(), refreshBoundary()]);
  if (!fresh) {
    addNote(
      'Connected over MCP. Ask the wearable a question, or press the injection button to ' +
        'watch a bystander instruction get reported instead of obeyed.',
    );
  }

  function failed(error) {
    setBadge('error', 'not connected');
    addError(`Could not reach ${base}/mcp — ${error.message}`);
    showOnboard('bad', {
      title: 'No bridge at this address',
      lead: `Nothing answered at ${base}/mcp, so there is nothing to demo yet.`,
      steps: [
        'Start the bridge with |npm run start:bee — it listens on 127.0.0.1:8791 by default.',
        'Or set a different port with |BEE_BRIDGE_PORT=9000 npm run start:bee and put that ' +
          'origin in the box below.',
        'Open this page from the bridge itself rather than from disk: the bridge is local-only ' +
          'and sends no CORS headers, so a |file:// page is blocked by the browser.',
      ],
    });
  }
}

base = initialBase();
$('baseUrl').value = base;
void boot();
