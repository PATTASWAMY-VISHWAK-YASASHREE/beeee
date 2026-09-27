/**
 * In-memory transcript store for the Wristbox stand-in.
 *
 * Deliberately in-memory and nothing else. These are spoken words, and the
 * least surprising thing to do with them is hold them for the length of a demo
 * and let them go. There is no database, no file, no write path, which also
 * means there is nothing to leak later.
 *
 * The rendering methods emit the same markdown shape the real Bee CLI emits,
 * for a concrete reason: the sanitiser in `src/bee/sanitize.ts` is tuned
 * against that shape, and a stand-in that invented its own format would be
 * testing the wrong parser.
 */

export interface Turn {
  id: string;
  /** Epoch milliseconds. */
  at: number;
  /**
   * Monotonic insertion counter.
   *
   * Exists because `at` is not sufficient. Two turns captured in the same
   * millisecond get identical timestamps -- and live speech does exactly that
   * during a fast exchange -- at which point a recency tie-break silently
   * becomes insertion order, returning the *older* turn. That contradicts what
   * the tie-break claims to do, and a stable sort will not save you.
   */
  seq: number;
  /** Who spoke, e.g. "Speaker 1". A bystander is just a different speaker. */
  speaker: string;
  text: string;
}

/** Cap so a long demo cannot grow without bound. */
const MAX_TURNS = 500;

export class TranscriptStore {
  private turns: Turn[] = [];
  private nextId = 1;
  private seq = 0;

  add(speaker: string, text: string): Turn {
    const turn: Turn = {
      id: `turn_${this.nextId++}`,
      at: Date.now(),
      seq: this.seq++,
      // Truncated hard: this is speech to be recalled, not a document store.
      speaker: (speaker || 'Speaker 1').slice(0, 40),
      text: (text || '').slice(0, 4000),
    };
    this.turns.push(turn);
    if (this.turns.length > MAX_TURNS) this.turns.splice(0, this.turns.length - MAX_TURNS);
    return turn;
  }

  all(): Turn[] {
    return [...this.turns];
  }

  recent(limit: number): Turn[] {
    return this.turns.slice(-limit);
  }

  count(): number {
    return this.turns.length;
  }

  clear(): void {
    this.turns = [];
    this.nextId = 1;
  }

  /**
   * Naive term search, ranked by how many terms a turn matched.
   *
   * Deliberately not clever. This stand-in exists to get real, unpredictable
   * speech in front of the sanitiser, not to pretend to be a search engine —
   * and a fancier matcher would risk quietly dropping exactly the awkward
   * phrasing we most want to test.
   */
  search(query: string, limit: number): Turn[] {
    const terms = query
      .toLowerCase()
      .split(/[^\p{L}\p{N}]+/u)
      .filter((t) => t.length > 1);
    if (terms.length === 0) return this.recent(limit);

    return this.turns
      .map((turn) => {
        const haystack = turn.text.toLowerCase();
        const hits = terms.filter((t) => haystack.includes(t)).length;
        return { turn, hits };
      })
      .filter((r) => r.hits > 0)
      // More matched terms wins; a tie goes to the more recent turn, using the
      // sequence number so that same-millisecond captures still order correctly.
      .sort((a, b) => b.hits - a.hits || b.turn.seq - a.turn.seq)
      .slice(0, limit)
      .map((r) => r.turn);
  }

  /** One "conversation" per contiguous block, mirroring how Bee groups them. */
  private conversations(limit: number): Turn[][] {
    const blocks: Turn[][] = [];
    for (const turn of this.turns) {
      const last = blocks[blocks.length - 1];
      // A gap over a minute starts a new conversation.
      if (last && turn.at - last[last.length - 1]!.at < 60_000) last.push(turn);
      else blocks.push([turn]);
    }
    return blocks.slice(-limit);
  }

  /** Markdown transcript, matching the real CLI's `# Conversation N` shape. */
  renderConversation(block: Turn[], index: number): string {
    const started = new Date(block[0]!.at).toISOString();
    return [
      `# Conversation ${100 + index}`,
      `- start_time: ${started}`,
      '- state: processed',
      '',
      '## Transcriptions',
      ...block.map((t) => `${t.speaker}: ${t.text}`),
    ].join('\n');
  }

  /** `bee_search` / `bee_get_conversation`. */
  searchMarkdown(query: string, limit: number): string {
    const blocks = this.conversations(50);
    const matched = this.search(query, limit);
    if (matched.length === 0) {
      return `No conversations matched "${query}". ${this.count()} turns are stored.`;
    }
    // Group the matched turns back into the blocks they came from.
    const ids = new Set(matched.map((t) => t.id));
    const chosen = blocks
      .filter((b) => b.some((t) => ids.has(t.id)))
      .slice(-limit)
      .map((b, i) => this.renderConversation(b, i));
    return chosen.join('\n\n');
  }

  /** `bee_now` — the most recent turns. */
  nowMarkdown(limit: number): string {
    const recent = this.recent(limit);
    if (recent.length === 0) return 'Nothing has been captured yet. Speak, or send a turn to /ingest.';
    return recent.map((t) => `${t.speaker}: ${t.text}`).join('\n');
  }

  /** `bee_today` — a spoken-length digest. */
  todayMarkdown(): string {
    if (this.turns.length === 0) {
      return 'Nothing has been captured yet. Speak, or send a turn to /ingest.';
    }
    const speakers = [...new Set(this.turns.map((t) => t.speaker))];
    const first = new Date(this.turns[0]!.at).toISOString();
    const last = new Date(this.turns[this.turns.length - 1]!.at).toISOString();
    return [
      `## ${this.turns.length} turns captured`,
      `- from: ${first}`,
      `- to: ${last}`,
      `- speakers: ${speakers.join(', ')}`,
      '',
      ...this.recent(5).map((t) => `${t.speaker}: ${t.text}`),
    ].join('\n');
  }

  /** `bee_list_facts` — derived, and labelled as derived, because it is. */
  factsMarkdown(): string {
    const facts = this.turns
      .filter((t) => /\b(decided|decision|we will|we're going to|agreed)\b/i.test(t.text))
      .slice(-10);
    if (facts.length === 0) {
      return '# Facts\n\n## Confirmed\n\n- No decision-shaped turns captured yet.';
    }
    return [
      '# Facts',
      '',
      '## Confirmed',
      ...facts.map(
        (t) => `- ${t.text.replace(/\s+/g, ' ').trim()} (${new Date(t.at).toISOString()}, id ${t.id})`,
      ),
    ].join('\n');
  }

  /** `bee_list_todos` — derived from imperative/negotiated phrasing. */
  todosMarkdown(): string {
    const todos = this.turns
      .filter((t) => /\b(need to|should|remember to|follow up|action item|let us|we'll)\b/i.test(t.text))
      .slice(-10);
    if (todos.length === 0) {
      return '# Todos\n\n## Open\n\n- No action items captured yet.';
    }
    return [
      '# Todos',
      '',
      '## Open',
      ...todos.map(
        (t) => `- ${t.text.replace(/\s+/g, ' ').trim()} (id ${t.id}, created ${new Date(t.at).toISOString()})`,
      ),
    ].join('\n');
  }
}
