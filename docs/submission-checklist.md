# Bee track — submission readiness

**Deadline:** Oct 23, 2026 @ 12:00pm PDT. **Prize:** $12,000 (1st), $8,000 (2nd).

Checklist derived from <https://amazonappdev2026.devpost.com/resources> and
<https://amazonappdev2026.devpost.com/>. Tick honestly — an unchecked box is
fine, a claim that does not survive a judge's five minutes is not.

## Required artefacts

| # | Item | State | Evidence |
| --- | --- | --- | --- |
| 1 | **Working demo** | Done | `npm run start:bee` → <http://127.0.0.1:8791>. Demo client in `public-bee/`. |
| 2 | **Code repo** | **Needs a remote** | No git remote is configured. See §1 below. |
| 3 | **Product feedback** | Drafted | §3 below. Required field. |
| 4 | Primary track selected | Done | Bee. |
| 5 | Build/significantly update during window | To confirm | The project did not exist before the hackathon. |

## 1. Blockers to clear before submitting

- [ ] **Create the public repo and push.** `git remote -v` is empty. Nothing can
      be submitted until this exists, and it is the only hard blocker left.
- [ ] **Decide the repo identity.** This working copy contains *two* projects:
      Bee Bridge (the submission) and Hermes Bridge (the Alexa+ entry). A judge
      landing on a mixed root will not know which one to look at. Cleanest fix
      is a dedicated repo containing the Bee half only, with `README.bee.md` as
      the root README.
- [ ] **Attach a demo video** if a live wearable is not available to judges.
- [ ] **Ask the two open questions** in §3 at live office hours — the hardware
      requirement is the one fact that changes what the demo can be.

## 2. Demo script (three minutes)

The demo is the trust boundary. Do not spend it on features.

1. **The problem (30s).** *"An agent can see what changed. It cannot see why.
   Bee already captured why. This connects them."*
2. **Normal recall (45s).** Ask a real question. Show the fenced, untrusted
   transcript *and* the Notes section. Point out that it is attributed and
   summarised, not obeyed.
3. **The attack (60s).** Press **"Try the injection attack."** The WARNING
   banner appears. *"That is what a bystander can get into your agent's context
   just by speaking. It was reported, and it was not obeyed."*
4. **Read-only (30s).** `bee_status`. Show the allow-list and the refused
   `bee_delete_conversation`.
5. **Redaction (15s).** Show a recall that masked a phone number, and that the
   server said it did.

**If asked "does it need the wearable?"** — yes for real data, and that is a Bee
limitation, not ours. The rules require a working demo, not hardware. Then show
that the entire pipeline is tested against a protocol-accurate fake: 117 unit
tests, 12 integration tests against a live subprocess, 30 smoke checks.

## 3. Product feedback (draft)

Devpost asks: which track(s), which mini-challenges, what did you build during
the window, feature requests, and **friction log entries**.

> **Tracks:** Bee. **Mini-challenges:** none.
>
> **What we built:** Bee Bridge, a read-only MCP server plus an Agent Skill that
> gives a coding agent the reasoning behind a decision — the design argument
> from a standup, the bug report from a user — which exists in no ticket and no
> commit message. The interesting part is the threat model: because Bee is
> ambient and does speaker identification, its transcripts are
> third-party-controlled input, so anyone in earshot can attempt prompt
> injection simply by speaking. The server redacts, fences with a per-call
> nonce, detects injection, and provides no path from recalled text to an
> authorisation.
>
> **Feature request 1 (critical):** a documented answer on whether Developer
> Mode works without the physical wearable paired, and ideally a simulator or
> seeded sandbox account. A CLI/MCP integration cannot be demoed or tested
> without hardware, and there is no simulator — the README names the Bee app as
> the only prerequisite, which is ambiguous.
>
> **Feature request 2 (high):** an official `bee` reference MCP server fixture
> for tests. Integrators currently have to hand-roll a fake subprocess to test
> transport, which is real work and a common source of bugs.


## 4. Friction log — worth up to 10% judging bonus

> Submissions with friction logs can earn up to a 10% judging bonus, so this is
> the highest-leverage non-code task left. Entries must be specific: the task
> attempted, steps taken, what was expected, what happened, severity, workaround,
> and an actionable suggestion.

| # | Task | Expected | Actual | Severity | Workaround |
| --- | --- | --- | --- | --- | --- |
| 1 | Determine whether a wearable is required to build a Bee integration | The docs or the track brief would state the requirement | The Bee brief has **no** hardware clause, and the docs name only "the Bee app" for Developer Mode. Whether the physical device must be paired is never stated. | **Critical** — it determines whether a demo is possible at all | Built a protocol-accurate fake `bee` and tested the full pipeline against it. |
| 2 | Test a stdio MCP client against a stub on Windows | A stub script, or a documented way to point the client at one | `spawn` with `shell: false` (correctly, for injection safety) cannot run a `.cmd` shim, so there is no idiomatic way to substitute a test double. | High | Pointed `BEE_BIN` at `node` and resolved the `mcp` subcommand against a fixture on disk. Non-obvious; a first-time builder would lose hours. |
| 3 | Discover whether `bee mcp serve` requires Developer Mode before it will return data | Documented in `bee mcp serve --help` or the docs | Not documented on the docs site or in the CLI README. | Medium | None; documented in our README. |

## 5. Judging-criteria prep

Judging is **tech implementation**, **design**, **potential impact**, **quality
of idea**. Map each to something demonstrable:

- **Tech implementation** — the trust boundary, five layers, 117 tests, real
  subprocess integration, spec-compliant transport. Concrete and hard to dismiss.
- **Design** — voice-first, read-only by construction; the demo client renders
  untrusted content as visibly quoted evidence.
- **Potential impact** — every team that uses a wearable AI *and* a coding agent
  hits this exact gap. It is not a demo-shaped problem.
- **Quality of idea** — reframing "an ambient wearable's transcript" as an
  *untrusted input channel* is a genuinely different angle from "let my agent
  read my memory", which is what the obvious entry would do.
