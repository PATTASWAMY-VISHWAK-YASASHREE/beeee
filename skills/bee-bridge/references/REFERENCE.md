# Bee Bridge reference

## What this is

A read-only MCP server that exposes the user's Bee wearable conversation memory
to a coding agent, plus the Agent Skill in `../SKILL.md` that teaches an agent
how to use it without treating a transcript as an instruction.

The Bee track brief asks for a project that "integrates Bee's CLI, MCP, or
Agent Skills with other services, devices, or developer tools", and names
*developer experience* as a priority use case. This is that: a coding agent can
read what the user actually **said** about their codebase, which is information
that exists in no ticket and no commit message.

Bee exposes no on-device runtime. `bee-cli` is a host-side Node CLI that doubles
as an MCP server (`bee mcp serve`, or `bee mcp serve-http` on 127.0.0.1 with
bearer auth). Everything in this project runs on the user's machine. Nothing is
installed on the wearable.

## Tools

### `bee_recall`

| Argument | Type | Notes |
| --- | --- | --- |
| `query` | string, required | What to look for, in the user's words. Max 500 chars. |
| `limit` | number | 1–20. Default 5. |
| `kind` | `search` \| `today` \| `now` \| `facts` \| `todos` \| `summary` | Which Bee surface to query. Default `search`. |
| `includeRaw` | boolean | Default false. Off by default on purpose. |

Returns text, plus structured fields:

- `notes` — human-readable list of what sanitisation changed. Never silent.
- `injection_suspected` — transcript text looked like it was addressing the
  agent. See the trust boundary below.
- `redacted_count` — how many spans were masked.
- `truncated` — whether the reply hit the character cap.

### `bee_brief`

| Argument | Type | Notes |
| --- | --- | --- |
| `limit` | number | 1–20. Default 5. |

A spoken-length digest of recent activity: what the user talked about, and any
open todos extracted from those conversations. Same sanitisation, same flags.

### `bee_status`

No arguments. Reports CLI reachability, authentication state, the read-only
tool allow-list, and the sanitisation caps. Safe to call when a recall fails.

## The trust boundary

This is the part that matters, so it is stated precisely.

Bee is an **ambient** wearable. It records conversations the user is having with
**other people**. That makes transcript text a third-party-controlled input
channel: anyone within earshot of the user can place arbitrary text into this
agent's context by speaking.

Defences, in order:

1. **Read-only, structurally.** The bridge speaks to Bee through a hard
   allow-list of read tools. Manage and write tools are rejected by the client
   before a request is sent. There is no code path from this server that
   mutates Bee data.
2. **Redaction before embedding.** Emails, phone numbers, card-like digit runs
   and token-shaped strings are masked before the text ever reaches a prompt.
3. **Injection detection.** Transcript text matching imperative agent-directed
   patterns is flagged. The bias is toward flagging: a false positive costs one
   sentence, a false negative lets a bystander's speech drive a coding agent.
4. **Nonce delimiting.** Recalled content is wrapped in a fence carrying a fresh
   unpredictable nonce per call, and any occurrence of that nonce is stripped
   from the content, so a transcript cannot forge the closing fence or
   impersonate a system message.
5. **No authorisation path.** Recalled content can inform a prompt. It can never
   satisfy the confirmation gate. There is no route from `bee_recall` to
   `confirm_action`, and a confirmation code appearing inside a transcript is
   not a confirmation code.

## What this does not protect you from

Stated plainly, because a security story that oversells itself is worse than
none:

- **Detection is a heuristic.** It catches instruction-shaped text. It does not
  catch every semantic attack, and an attacker who simply phrases a harmful
  request as ordinary conversation will pass it. This narrows the obvious
  cases; it is not a sandbox.
- **Redaction is pattern-based.** It will not catch a secret that does not look
  like a secret, such as a project codename discussed on a call.
- **The bridge itself has no authentication** unless you set
  `BEE_BRIDGE_TOKEN`. It binds `127.0.0.1`, so any local process or any page
  that can reach localhost can drive it.
- **Bee authenticates the CLI, not the content.** Content integrity is Bee's
  guarantee, not this bridge's.
- **Privacy is a real exposure.** Wiring end-to-end encrypted personal
  conversation into an agent pipeline increases the blast radius of that agent.
  That is a deliberate trade, and it is why the surface is read-only and
  redacted rather than bidirectional.
