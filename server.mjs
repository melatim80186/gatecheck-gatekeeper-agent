// GateCheck — zkVerify Agent Games, Proof Gatekeeper track
// A deterministic gatekeeper: it checks the task payload's own fields
// against the registered condition and returns APPROVE / REJECT, with a
// Groth16 proof of the decision (snarkjs + official gatekeeper circuit)
// attached when provable. When proving fails, the decision is returned
// WITHOUT a proof — a correct proof-less decision still scores +10,
// while an attached bad proof would score -2.
//
// Node 22 stdlib only — no dependencies, runs anywhere (Render, Fly.io,
// Railway, any VPS). No private keys, no wallet, no funds, no outbound
// network calls: every check runs on the payload fields, so decisions
// are instant (well inside the platform's 60 s hard deadline).
//
// Env:
//   PORT               (default 8080)
//   AGENT_HMAC_SECRET  secret issued once by the Agent Games dashboard
//                      at agent registration ("Rotate Secret"). If unset,
//                      responses are unsigned (health/task still work) —
//                      set it before preflight. The HMAC secret must match
//                      the platform-generated value — never a placeholder.
//
// Endpoints:
//   GET  /         protocol-v1 health check -> {"ok":true,"protocolVersion":"v1"}
//                   (the platform preflights the registered endpoint with a
//                   GET and requires exactly this signed JSON — see the
//                   preflight error 2026-11-18: the agent card used to live
//                   here and failed the check for a missing protocolVersion)
//   GET  /health   same protocol-v1 health check
//   GET  /agent    same protocol-v1 health check (in case the endpoint was
//                   registered with the /agent path)
//   GET  /info     agent card (human-readable, was GET / before the fix)
//   POST /         task payload -> decision JSON, EXCEPT a preflight
//                   envelope {"type":"agent-games.preflight.v1"}, which is
//                   answered {"ok":true,"protocolVersion":"v1"} (signed).
//                   The platform preflights with a POST envelope, NOT a GET:
//                   fix 1 (GET body) and fix 2 (bare-hex signature) were
//                   both necessary but not sufficient — a preflight POST
//                   used to fall through to decide() and come back REJECT
//                   VK_SUBSTITUTION, which the platform reads as a protocol
//                   failure. (Confirmed from a live passing implementation,
//                   2026-11-18.)
//   POST /task     same as POST /
//   POST /agent    same as POST / (in case the endpoint was registered
//                   with the /agent path)
//
// Signing (per the official build guide, agentgames.zkverify.io/build):
//   Every response carries header:
//     x-agent-games-signature: <hmac-sha256(secret, raw response body)>
//   Bare lowercase hex, NO "sha256=" prefix — the platform hex-decodes
//   the header value, so the prefixed form fails preflight.
//   Incoming tasks: the guide says to verify the HMAC signature against
//   the raw body before parsing, but does NOT name the incoming header.
//   GateCheck therefore checks a small set of candidate header names
//   (x-agent-games-signature, x-agent-signature, x-signature, signature)
//   and logs the result — verified / mismatch / absent — but NEVER
//   refuses a task over it: the header name/format is unconfirmed, and
//   dropping a scored task on a wrong guess would cost more than the
//   signature check gains. The dashboard at registration is the final
//   authority; if it names a different header or value format, that is
//   a 2-line change in signHeaders() / INCOMING_SIG_HEADERS below.
//
// Trap checks, in platform order (first hit wins):
//   1 PROOF_REUSED       proof_tx already accepted in an earlier task
//   2 VK_SUBSTITUTION    proof_vk != registered_vk (missing VKs count too)
//   3 THRESHOLD_MISMATCH public_balance < minimum (BigInt compare)
//   4 EXPIRED_CONDITION  current_block > expiry_block
//   5 RECIPIENT_MISMATCH recipient != condition_recipient (case-insensitive)
//   6 AMOUNT_OVERFLOW    amount > max_transfer (BigInt compare)
//   7 otherwise APPROVE with reason_code VALID_CONDITION
//
// Fail closed: missing / malformed / unparseable fields reject with the
// best-fit reason code (never crash, never time out). A REJECT decision
// is returned as HTTP 200 with the decision JSON — the platform wants a
// decision, not an error page.
import http from 'node:http';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { groth16 } from 'snarkjs';
import jsSha3 from 'js-sha3';
const { keccak256 } = jsSha3;

const PORT = Number(process.env.PORT || 8080);
const HMAC_SECRET = process.env.AGENT_HMAC_SECRET || '';
const SEEN_FILE = path.join(path.dirname(fileURLToPath(import.meta.url)), 'seen.json');
const MAX_BODY = 65536;

// Groth16 proof pipeline (added 2026-11-19): official gatekeeper circuit
// artifacts live in circuits/ (wasm + zkey, sha256-verified). If either
// file is missing, proofs are silently disabled and the agent keeps
// answering proof-less decisions (the pre-pipeline behavior).
const CIRCUIT_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), 'circuits');
const WASM_PATH = path.join(CIRCUIT_DIR, 'gatekeeper.wasm');
const ZKEY_PATH = path.join(CIRCUIT_DIR, 'gatekeeper_final.zkey');
// bn128 field prime — every circuit input is a field element.
const FIELD_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;
// Hard cap for proving, well inside the platform's 60 s response deadline.
const PROVE_TIMEOUT_MS = 20000;
const PROOFS_ENABLED = fs.existsSync(WASM_PATH) && fs.existsSync(ZKEY_PATH);

// ---------------------------------------------------------------------------
// Seen-set: proof_tx values accepted in earlier APPROVE decisions.
// Kept in memory and persisted to seen.json on disk (best-effort).
// NOTE: Render free-tier disk is ephemeral across deploys/restarts, so
// reuse detection is best-effort — a redeploy can forget earlier proofs.
// ---------------------------------------------------------------------------
const seen = new Set();
try {
  const raw = JSON.parse(fs.readFileSync(SEEN_FILE, 'utf8'));
  if (Array.isArray(raw)) {
    for (const tx of raw) if (typeof tx === 'string' && tx) seen.add(tx);
  }
  console.log(`[gatecheck] loaded ${seen.size} seen proof_tx from seen.json`);
} catch {
  console.log('[gatecheck] no usable seen.json — starting with an empty seen-set');
}

function saveSeen() {
  try {
    fs.writeFileSync(SEEN_FILE, JSON.stringify([...seen], null, 2) + '\n');
  } catch (e) {
    // Best-effort only: a failed disk write must never break a decision.
    console.error(`[gatecheck] WARN could not persist seen.json: ${e.message}`);
  }
}

// Signing — the platform's exact scheme (confirmed from a live passing
// implementation, 2026-11-18): HMAC-SHA256, lowercase hex, NO prefix,
// over the exact raw response body bytes, in x-agent-games-signature.
// The "sha256=<hex>" form FAILS preflight: the platform hex-decodes the
// header value and "sha256=" is not valid hex. (Preflight failed twice
// with that format before this fix.)
function signHeaders(body) {
  if (!HMAC_SECRET) return {};
  const sig = crypto.createHmac('sha256', HMAC_SECRET)
    .update(Buffer.from(body, 'utf8'))
    .digest('hex');
  return { 'x-agent-games-signature': sig };
}

function send(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, { 'content-type': 'application/json', ...signHeaders(body) });
  res.end(body);
}

// ---------------------------------------------------------------------------
// Incoming signature verification (best-effort — see header comment).
// Returns { checked, ok, detail } and never throws.
// ---------------------------------------------------------------------------
const INCOMING_SIG_HEADERS = [
  'x-agent-games-signature',
  'x-agent-signature',
  'x-signature',
  'signature',
];

function verifyIncoming(req, rawBody) {
  if (!HMAC_SECRET) return { checked: false, ok: false, detail: 'no secret configured' };
  const headerName = INCOMING_SIG_HEADERS.find((h) => req.headers[h] !== undefined);
  if (!headerName) {
    return { checked: false, ok: false, detail: 'no signature header present (pending dashboard confirmation)' };
  }
  const presented = String(req.headers[headerName]).replace(/^sha256=/i, '').trim();
  const expected = crypto.createHmac('sha256', HMAC_SECRET).update(rawBody).digest('hex');
  let ok = false;
  try {
    ok = presented.length === expected.length &&
      crypto.timingSafeEqual(Buffer.from(presented, 'utf8'), Buffer.from(expected, 'utf8'));
  } catch { ok = false; }
  return { checked: true, ok, detail: ok ? `verified via ${headerName}` : `MISMATCH via ${headerName}` };
}

// ---------------------------------------------------------------------------
// Decision logic
// ---------------------------------------------------------------------------
function normAddr(a) {
  return typeof a === 'string' ? a.trim().toLowerCase() : '';
}

// Decimal string / number / bigint -> BigInt, or null if unparseable.
function toBig(v) {
  try {
    if (typeof v === 'bigint') return v;
    if (typeof v === 'number' && Number.isInteger(v)) return BigInt(v);
    if (typeof v === 'string' && /^-?\d+$/.test(v.trim())) return BigInt(v.trim());
    return null;
  } catch { return null; }
}

function decide(task) {
  const input = (task && typeof task === 'object' &&
    task.input && typeof task.input === 'object') ? task.input : {};
  const proofTx = typeof input.proof_tx === 'string' && input.proof_tx ? input.proof_tx : null;

  // 1) PROOF_REUSED — proof_tx already accepted in a previous task.
  if (proofTx && seen.has(proofTx)) {
    return { decision: 'REJECT', reason_code: 'PROOF_REUSED', proof_tx: proofTx };
  }

  // 2) VK_SUBSTITUTION — proof_vk must equal registered_vk.
  //    Missing either VK fails closed as a substitution.
  const regVk = typeof input.registered_vk === 'string' ? input.registered_vk.trim().toLowerCase() : '';
  const proofVk = typeof input.proof_vk === 'string' ? input.proof_vk.trim().toLowerCase() : '';
  if (!regVk || !proofVk || regVk !== proofVk) {
    return { decision: 'REJECT', reason_code: 'VK_SUBSTITUTION', proof_tx: proofTx };
  }

  // 3) THRESHOLD_MISMATCH — public_balance must be >= minimum.
  const bal = toBig(input.public_balance);
  const min = toBig(input.minimum);
  if (bal === null || min === null || bal < min) {
    return { decision: 'REJECT', reason_code: 'THRESHOLD_MISMATCH', proof_tx: proofTx };
  }

  // 4) EXPIRED_CONDITION — current_block must be <= expiry_block.
  const cur = toBig(input.current_block);
  const exp = toBig(input.expiry_block);
  if (cur === null || exp === null || cur > exp) {
    return { decision: 'REJECT', reason_code: 'EXPIRED_CONDITION', proof_tx: proofTx };
  }

  // 5) RECIPIENT_MISMATCH — recipient must equal condition_recipient.
  const recip = normAddr(input.recipient);
  const condRecip = normAddr(input.condition_recipient);
  if (!recip || !condRecip || recip !== condRecip) {
    return { decision: 'REJECT', reason_code: 'RECIPIENT_MISMATCH', proof_tx: proofTx };
  }

  // 6) AMOUNT_OVERFLOW — amount must be <= max_transfer.
  const amt = toBig(input.amount);
  const max = toBig(input.max_transfer);
  if (amt === null || max === null || amt > max) {
    return { decision: 'REJECT', reason_code: 'AMOUNT_OVERFLOW', proof_tx: proofTx };
  }

  // 7) All checks pass.
  return { decision: 'APPROVE', reason_code: 'VALID_CONDITION', proof_tx: proofTx };
}

// ---------------------------------------------------------------------------
// Groth16 proof pipeline (added 2026-11-19 — R06 scored 8/8 correct at
// +10 each without proofs; a valid proof lifts each correct decision to
// +12 and counts toward the reliability bonus).
//
// Circuit: official gatekeeper circuit (GatekeeperEvaluation_79, 647
// witness signals, 13 public signals), Groth16/BN128, artifacts in
// circuits/. Input signal names and encodings were recovered by probing
// the compiled WASM and validated by reproducing a published test vector
// EXACTLY (12 of 13 public signals identical, Poseidon commitment
// formula verified with circomlibjs):
//   registeredVkHash / proofVkHash : BigInt(hex VK string) mod p
//     (the task's VK fields ARE verification-key hashes — fed directly,
//     NOT hashed again)
//   minimum / publicBalance / expiryBlock / currentBlock / amount /
//   maxTransfer : plain integers from the task fields
//   recipient / conditionRecipient : plain integers from the hex address
//   decision : 1 = APPROVE, 0 = REJECT
//   taskId : keccak256(task_id ASCII string) mod p
//   salt : random private field element (never leaves the prover)
// Public signals: [Poseidon(salt, taskId) commitment, registeredVkHash,
// proofVkHash, minimum, publicBalance, expiryBlock, currentBlock,
// recipient, conditionRecipient, amount, maxTransfer, decision, taskId].
// Response shape (per the official starter prompt on /build):
//   { decision, reason_code, proof, public_signals }
// where proof is the raw snarkjs Groth16 proof object and public_signals
// is the 13-element array of decimal strings.
//
// The circuit enforces decision == the computed verdict: a proof can
// only be built for the CORRECT decision. A wrong decision cannot even
// build a witness (assert at GatekeeperEvaluation_79 line 102), so
// proving a decision the circuit disagrees with THROWS — caught below
// and falls back to the proof-less response. The one systematic case:
// PROOF_REUSED rejections (all circuit checks pass, but the decision
// must be REJECT) can never be proven — they always fall back.
// ---------------------------------------------------------------------------
function hexToField(hexStr) {
  if (typeof hexStr !== 'string' || !/^0x[0-9a-fA-F]+$/.test(hexStr.trim())) {
    throw new Error(`not a hex value: ${String(hexStr).slice(0, 20)}`);
  }
  return BigInt(hexStr.trim()) % FIELD_PRIME;
}

function fieldFromBig(v, name) {
  if (v === null || v < 0n || v >= FIELD_PRIME) throw new Error(`field out of range: ${name}`);
  return v;
}

function buildCircuitInput(task, decision) {
  const input = (task && typeof task === 'object' &&
    task.input && typeof task.input === 'object') ? task.input : {};
  const regVk = typeof input.registered_vk === 'string' ? input.registered_vk : '';
  const proofVk = typeof input.proof_vk === 'string' ? input.proof_vk : '';
  // Addresses parse as field elements as-is (any length of valid hex);
  // hexToField/fieldFromBig below throw on malformed or out-of-range
  // values, and the caller falls back to the proof-less response.
  const recip = normAddr(input.recipient);
  const condRecip = normAddr(input.condition_recipient);
  if (typeof task.task_id !== 'string' || !task.task_id) {
    throw new Error('missing task_id');
  }
  const min = toBig(input.minimum);
  const bal = toBig(input.public_balance);
  const exp = toBig(input.expiry_block);
  const cur = toBig(input.current_block);
  const amt = toBig(input.amount);
  const max = toBig(input.max_transfer);
  // Random private salt (field element, never 0).
  let salt = 0n;
  for (let i = 0; i < 5 && salt === 0n; i++) {
    salt = BigInt('0x' + crypto.randomBytes(32).toString('hex')) % FIELD_PRIME;
  }
  if (salt === 0n) throw new Error('could not sample a non-zero salt');
  return {
    registeredVkHash: hexToField(regVk).toString(),
    proofVkHash: hexToField(proofVk).toString(),
    minimum: fieldFromBig(min, 'minimum').toString(),
    publicBalance: fieldFromBig(bal, 'public_balance').toString(),
    expiryBlock: fieldFromBig(exp, 'expiry_block').toString(),
    currentBlock: fieldFromBig(cur, 'current_block').toString(),
    recipient: fieldFromBig(hexToField(recip), 'recipient').toString(),
    conditionRecipient: fieldFromBig(hexToField(condRecip), 'condition_recipient').toString(),
    amount: fieldFromBig(amt, 'amount').toString(),
    maxTransfer: fieldFromBig(max, 'max_transfer').toString(),
    decision: decision === 'APPROVE' ? '1' : '0',
    taskId: (BigInt('0x' + keccak256(task.task_id)) % FIELD_PRIME).toString(),
    salt: salt.toString(),
  };
}

// Best-effort proving: returns { proof, publicSignals } or null.
// NEVER throws. Any failure (unbuildable input, witness assert, proving
// error, timeout) returns null and the caller sends the proof-less
// decision — a correct proof-less decision still scores +10, while an
// attached bad proof would score -2.
async function proveDecision(task, decision, taskId) {
  if (!PROOFS_ENABLED) return null;
  let input;
  try {
    input = buildCircuitInput(task, decision);
  } catch (e) {
    console.log(`[${new Date().toISOString()}] task_id=${taskId} proof skipped (input unbuildable: ${e.message})`);
    return null;
  }
  try {
    const t0 = Date.now();
    const { proof, publicSignals } = await Promise.race([
      groth16.fullProve(input, WASM_PATH, ZKEY_PATH),
      new Promise((_, reject) => setTimeout(() => reject(new Error('prove timeout')), PROVE_TIMEOUT_MS)),
    ]);
    console.log(`[${new Date().toISOString()}] task_id=${taskId} proof built in ${Date.now() - t0} ms (decision=${decision})`);
    return { proof, publicSignals };
  } catch (e) {
    console.log(`[${new Date().toISOString()}] task_id=${taskId} proof skipped (${e.message})`);
    return null;
  }
}

// ---------------------------------------------------------------------------
// HTTP plumbing
// ---------------------------------------------------------------------------
function readRawBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY) { req.destroy(); reject(new Error('body too large')); return; }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

async function handleTask(req, res) {
  let raw;
  try {
    raw = await readRawBody(req);
  } catch {
    console.log(`[${new Date().toISOString()}] task_id=? decision=REJECT reason=VK_SUBSTITUTION (unreadable body)`);
    return send(res, 200, { decision: 'REJECT', reason_code: 'VK_SUBSTITUTION', proof_tx: null });
  }

  const incoming = verifyIncoming(req, raw);

  let task = null;
  try {
    task = JSON.parse(raw.toString('utf8'));
  } catch {
    console.log(`[${new Date().toISOString()}] task_id=? decision=REJECT reason=VK_SUBSTITUTION (malformed JSON) incoming_sig=${incoming.detail}`);
    return send(res, 200, { decision: 'REJECT', reason_code: 'VK_SUBSTITUTION', proof_tx: null });
  }
  if (!task || typeof task !== 'object') {
    console.log(`[${new Date().toISOString()}] task_id=? decision=REJECT reason=VK_SUBSTITUTION (empty/non-object body) incoming_sig=${incoming.detail}`);
    return send(res, 200, { decision: 'REJECT', reason_code: 'VK_SUBSTITUTION', proof_tx: null });
  }

  // Preflight handshake: the platform POSTs {"type":"agent-games.preflight.v1"}
  // to the registered endpoint and requires {"ok":true,"protocolVersion":"v1"},
  // signed. This must be answered BEFORE decide() — a preflight envelope has
  // no input, so decide() would fail it closed as VK_SUBSTITUTION.
  if (typeof task.type === 'string' && task.type.startsWith('agent-games.preflight')) {
    console.log(`[${new Date().toISOString()}] preflight handshake answered (type=${task.type}) incoming_sig=${incoming.detail}`);
    return send(res, 200, { ok: true, protocolVersion: 'v1' });
  }

  let out;
  try {
    out = decide(task);
  } catch (e) {
    // Last-resort fail closed — decide() is pure, this should never fire.
    console.error(`[gatecheck] ERROR decide() threw: ${e.message}`);
    out = { decision: 'REJECT', reason_code: 'VK_SUBSTITUTION', proof_tx: null };
  }

  if (out.decision === 'APPROVE' && out.proof_tx) {
    seen.add(out.proof_tx);
    saveSeen();
  }

  // Groth16 proof (best-effort, never blocks or changes the decision).
  const taskId = task.task_id || '?';
  const proved = await proveDecision(task, out.decision, taskId);
  const response = { ...out };
  if (proved) {
    response.proof = proved.proof;
    response.public_signals = proved.publicSignals;
  }

  console.log(`[${new Date().toISOString()}] task_id=${taskId} mode=${task.mode || '?'} decision=${out.decision} reason=${out.reason_code} proof_tx=${out.proof_tx} proof=${proved ? 'attached' : 'none'} incoming_sig=${incoming.detail}`);
  return send(res, 200, response);
}

const server = http.createServer(async (req, res) => {
  try {
    const url = req.url.split('?')[0];
    // Protocol-v1 health check: the platform GETs the registered endpoint
    // (root, /health, or /agent) and requires exactly this signed JSON.
    if (req.method === 'GET' && (url === '/' || url === '/health' || url === '/agent')) {
      return send(res, 200, { ok: true, protocolVersion: 'v1' });
    }
    if (req.method === 'GET' && url === '/info') {
      return send(res, 200, {
        agent: 'GateCheck',
        track: 'zkVerify Agent Games — Proof Gatekeeper',
        idea: 'Deterministic gatekeeper: every task payload field is checked against the registered condition, in platform order, and answered APPROVE / REJECT with the matching reason code.',
        endpoints: ['GET /health', 'POST / {task}', 'POST /task {task}'],
        signed: Boolean(HMAC_SECRET),
        signature_header: 'x-agent-games-signature',
        proofs: 'Groth16 proof attached when provable (snarkjs + official gatekeeper circuit, circuits/); falls back to a proof-less decision when proving fails (correct proof-less decision scores +10, an attached bad proof would score -2)',
        seen_proofs: seen.size,
      });
    }
    if (req.method === 'POST' && (url === '/' || url === '/task' || url === '/agent')) {
      return handleTask(req, res);
    }
    return send(res, 404, { decision: 'REJECT', reason_code: 'VK_SUBSTITUTION', proof_tx: null });
  } catch (e) {
    console.error(`[gatecheck] ERROR ${req.method} ${req.url}: ${e.message}`);
    return send(res, 200, { decision: 'REJECT', reason_code: 'VK_SUBSTITUTION', proof_tx: null });
  }
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`GateCheck listening on ${PORT} (signed=${Boolean(HMAC_SECRET)}, seen=${seen.size}, proofs=${PROOFS_ENABLED ? 'enabled' : 'DISABLED — circuit files missing'})`);
});
