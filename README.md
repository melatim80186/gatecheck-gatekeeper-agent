# GateCheck — zkVerify Agent Games, Proof Gatekeeper

A deterministic gatekeeper agent for the **Proof Gatekeeper** track of
[zkVerify Agent Games](https://agentgames.zkverify.io) (Season 01,
21 Oct – 21 Nov 2026). The platform POSTs a task payload to our registered
HTTPS endpoint; GateCheck checks the payload's own fields against the
registered condition — in platform order — and returns one JSON decision
within the 60-second hard deadline. Decisions are instant: no network
calls, no wallet, no keys.

## Trap checks (in platform order — first hit wins)

| # | Trap | Condition | Decision |
|---|------|-----------|----------|
| 1 | `PROOF_REUSED` | `proof_tx` was already accepted in an earlier task (local seen-set) | REJECT |
| 2 | `VK_SUBSTITUTION` | `proof_vk != registered_vk` (missing VKs count as a mismatch) | REJECT |
| 3 | `THRESHOLD_MISMATCH` | `public_balance < minimum` (BigInt compare on decimal strings) | REJECT |
| 4 | `EXPIRED_CONDITION` | `current_block > expiry_block` | REJECT |
| 5 | `RECIPIENT_MISMATCH` | `recipient != condition_recipient` (case-insensitive) | REJECT |
| 6 | `AMOUNT_OVERFLOW` | `amount > max_transfer` (BigInt compare) | REJECT |
| 7 | — | all checks pass | **APPROVE `VALID_CONDITION`** |

~50% of tasks are valid; the rest are the traps above. Response shape:

```json
{"decision": "REJECT", "reason_code": "VK_SUBSTITUTION", "proof_tx": "0xa4c1...8ff1"}
```

`proof_tx` is echoed from the task input. Missing / malformed fields
**fail closed**: the agent REJECTs with the best-fit reason code
(e.g. missing VKs → `VK_SUBSTITUTION`, missing balance/minimum →
`THRESHOLD_MISMATCH`) and never crashes or times out. Every decision is
logged to stdout as `task_id, mode, decision, reason_code, proof_tx`.

## Scoring caveat — NO Groth16 proof (read this first)

**GateCheck returns decisions WITHOUT a Groth16 proof.** No proof is
generated, and no proof fields are faked — inventing one would be worse
than omitting it. Per the event scoring:

- correct APPROVE/REJECT: **+12**
- incorrect APPROVE: **−6** · incorrect REJECT: **−3** · timeout: **−2**
- **a correct decision without a valid Groth16 proof costs an extra −2
  and earns no reliability bonus.**

So a correct GateCheck decision scores **+10** instead of +12, and the
reliability bonus is forfeited. This is accepted for Rounds 04–08 while
the proof pipeline (Circom circuit + `.zkey`/WASM from
`/api/circuit-info`, local proving with `snarkjs`, Kurier submission)
is still unbuilt. Adding real proofs later is the single biggest
scoring upgrade available — it is a separate build, not a config tweak.

## Signing (official build guide)

Per https://agentgames.zkverify.io/build:

- **Responses:** every response is signed with header
  `x-agent-games-signature` = HMAC-SHA256(`AGENT_HMAC_SECRET`, raw
  response body). Value format is `sha256=<hex>` (common HMAC
  convention).
- **Incoming tasks:** the guide says to verify the HMAC signature
  against the raw body before parsing, but **does not name the incoming
  header**. GateCheck checks candidate headers
  (`x-agent-games-signature`, `x-agent-signature`, `x-signature`,
  `signature`) and logs the result — verified / mismatch / absent —
  but **never refuses a task over it**: the header name/format is
  unconfirmed, and dropping a scored task on a wrong guess would cost
  more than the check gains. The log line for every task records the
  incoming-signature state.
- **The dashboard at registration is the final authority.** If it names
  a different incoming header or a different value format
  (e.g. bare hex instead of `sha256=`), that is a 2-line change in
  `signHeaders()` / `INCOMING_SIG_HEADERS` in `server.mjs` — align it
  during registration and re-run `npm test`.

## Seen-set (proof-reuse memory)

Accepted `proof_tx` values are kept in memory **and** persisted to
`seen.json` on disk (best-effort — a failed write never breaks a
decision). **Caveat:** Render's free-tier disk is ephemeral across
deploys/restarts, so a redeploy can forget earlier proofs and reuse
detection is best-effort. A durable store (Render persistent disk or
an external KV) would fix this properly; with only 8 tasks per round
and 5 rounds left, the in-memory set is enough for a single run.

## Files

| File | What it is |
|------|-----------|
| `server.mjs` | The agent. Node 22 stdlib only, no dependencies. |
| `package.json` | `npm start` → `node server.mjs`; `npm test` → local test suite. |
| `render.yaml` | Render free web service `gatecheck`; `AGENT_HMAC_SECRET` via `sync: false`. |
| `seen.json` | Persisted seen-set (starts empty: `[]`). |
| `test-local.mjs` | Local test suite (trap matrix + signature verification). |

## Local test

```bash
cd gatekeeper-agent
npm test        # spawns the server on port 18099, runs 12+ checks, exits 0/1
```

Expected: all checks pass, including the sample payload from the event
page (→ `REJECT VK_SUBSTITUTION`), a fully-valid variant (→ `APPROVE
VALID_CONDITION`), re-posting that variant (→ `REJECT PROOF_REUSED`),
plus expired / threshold / recipient / amount variants, BigInt values
beyond 2^53, malformed JSON, and missing fields. The test resets
`seen.json` to `[]` when it finishes.

To run the server by hand:

```bash
AGENT_HMAC_SECRET=test-secret PORT=8080 node server.mjs
curl http://127.0.0.1:8080/health
curl -X POST http://127.0.0.1:8080/task -H 'content-type: application/json' \
  -d '{"type":"agent-games.proof-gatekeeper.v1","task_id":"gk_demo","mode":"practice","input":{"registered_vk":"0x7d3a...f291","proof_vk":"0x7d3a...f291","minimum":"1000","public_balance":"1460","expiry_block":19842201,"current_block":19832000,"recipient":"0xDe42...9f01","condition_recipient":"0xDe42...9f01","amount":"500","max_transfer":"1000","proof_tx":"0xabc...001"}}'
```

## Register (user-side steps — nothing here deploys or registers itself)

1. Deploy this directory to Render (New → Web Service → connect the repo
   → `render.yaml` auto-detected → **Free** tier). The service name is
   `gatecheck`.
2. zkVerify dashboard → **Manage Agents** → new agent, name **GateCheck**
   → paste the Render URL (`https://gatecheck.onrender.com`).
3. **Save the one-time HMAC secret** shown at registration, then set it
   as the `AGENT_HMAC_SECRET` environment variable in Render and
   **redeploy** (the secret must match the platform-generated value —
   never a local placeholder).
4. Wake the free tier: `GET https://gatecheck.onrender.com/health`
   (cold start takes ~30–60 s; if preflight times out, wake first, then
   retry preflight).
5. Run the **signed preflight**, then at least one **practice task**
   (`mode: "practice"` — same logic, unscored).
6. Enter the Proof Gatekeeper event. **Rounds:** daily 16:00–02:00 IST
   (17:30–03:30 WIB), 8 tasks per agent per round, cumulative scoring.
   Rounds 01–02 are done and Round 03 (15 Nov, 17:30 WIB) will be
   missed — **target Rounds 04–08 (16–20 Nov)**.

## What this agent does NOT do

- No Groth16 proof generation (see scoring caveat above).
- No on-chain calls, no wallet, no funds, no outbound network.
- No GitHub repo, no deployment, no dashboard registration — those are
  separate, user-side steps.
