# Wristbox — a local stand-in for a wearable

## This is not Bee

Wristbox is **not** Amazon's Bee product. It contains no Bee data, is not
affiliated with Amazon, and is not a simulator *of* Bee in any official sense —
Amazon does not ship one. It is a small local server that speaks the same MCP
tool surface so that a phone's microphone can stand in for a wearable while
testing.

Nothing in this project should ever be presented as a Bee integration working
without hardware. If a reviewer were to conclude that the team passed a stand-in
off as the real thing, that would be a lie — and a project whose entire argument
is *"the trust boundary has to be honest to be worth anything"* cannot afford
one.

## Why it exists

Amazon ships no simulator and no sandbox for Bee. That leaves two bad options:

1. Test only against a **fixed fixture** — one attack payload, written by us, so
   it tests the phrasing we already thought of.
2. Get hardware — which may not be available, and when it is, the demo is
   fragile.

Wristbox is the third option: **live, improvised speech**. You talk, it
transcribes, the real sanitiser processes it, and you can try an attack in words
nobody scripted. That is a genuinely better test of the actual threat model,
which is *"a bystander says something adversarial in a phrasing you did not
anticipate."*

It also mirrors the real product honestly: Bee is a wearable that pairs with a
phone. Your phone acting as the mic is the same shape, not a fake one.

## How to run it

Terminal one — the stand-in, on port 8792:

```bash
npm run wristbox:lan
```

`--lan` binds beyond loopback so a phone on the same Wi-Fi can reach it, and
prints the addresses to open. It also prints a bearer token, generated fresh per
run. Without `--lan` it binds to 127.0.0.1 and your phone cannot see it, which
is the safer default.

Terminal two — Bee Bridge, pointed at the stand-in:

```bash
BEE_MCP_TRANSPORT=http
BEE_MCP_HTTP_URL=http://127.0.0.1:8792/mcp
BEE_MCP_HTTP_TOKEN=<the token wristbox printed>
npm start
```

Open <http://127.0.0.1:8791>, speak into your phone, and ask a question.

## Things to be honest about

- **Browser speech recognition is not offline.** Chrome and Safari implement the
  Web Speech API by sending audio to the browser vendor for recognition. Your
  voice leaves the device and is *not* end-to-end encrypted. That is the
  opposite of the real wearable, and this page says so on its face.
- **Transcripts are in memory only.** No database, no file, nothing written to
  disk. They disappear when the process stops.
- **`/ingest` is an injection vector into the stand-in.** Anyone who can reach
  it can put text into the store, which is exactly the attack the project is
  about. It is therefore token-guarded, and LAN mode is opt-in. On an untrusted
  network, do not enable it.
- **Derived data is derived.** `bee_list_facts` and `bee_list_todos` are simple
  keyword matches over speech, not real extraction. They exist so the tool
  surface lines up, not because the logic is good.

## What it does and does not prove

**It does prove** that the whole path works end to end against speech that
nobody scripted, and it is how you check the detector against improvised
phrasings.

**It does not prove** anything about Bee itself — not its capture, not its
encryption, not its authentication, and not whether Developer Mode is required.
For that, see `npm run verify:bee` in the project root.

## Layout

```
dev/wristbox/store.ts    in-memory turns; renders Bee-shaped markdown
dev/wristbox/server.ts   MCP surface + /ingest + /state + the phone page
dev/wristbox/index.ts    entry point
dev/wristbox/public/     the phone capture page
```

The tool names match the real CLI exactly, because `READ_ONLY_TOOLS` in
`src/bee/client.ts` is an allow-list *by name* — rename one and the client will
refuse to call it, which is the correct failure mode.
