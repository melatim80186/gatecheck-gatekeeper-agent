// GateCheck — zkVerify Agent Games, Proof Gatekeeper track
// A deterministic gatekeeper: it checks the task payload's own fields
// against the registered condition and returns APPROVE / REJECT.
// No Groth16 proof is generated or attached (see README — scoring caveat).
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
//   POST /         task payload -> decision JSON
//   POST /task     same as POST /
//
// Signing (per the official build guide, agentgames.zkverify.io/build):
//   Every response carries header:
//     x-agent-games-signature: sha256=<hmac-sha256(secret, raw response body)>
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

const PORT = Number(process.env.PORT || 8080);
const HMAC_SECRET = process.env.AGENT_HMAC_SECRET || '';
const SEEN_FILE = path.join(path.dirname(fileURLToPath(import.meta.url)), 'seen.json');
const MAX_BODY = 65536;

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

// ---------------------------------------------------------------------------
// Signing — official scheme: x-agent-games-signature over the raw body.
// Value format "sha256=<hex>" follows the common HMAC convention; the
// dashboard at registration is the final authority on the exact format.
// ---------------------------------------------------------------------------
function signHeaders(body) {
  if (!HMAC_SECRET) return {};
  const sig = crypto.createHmac('sha256', HMAC_SECRET)
    .update(Buffer.from(body, 'utf8'))
    .digest('hex');
  return { 'x-agent-games-signature': `sha256=${sig}` };
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

  console.log(`[${new Date().toISOString()}] task_id=${task.task_id || '?'} mode=${task.mode || '?'} decision=${out.decision} reason=${out.reason_code} proof_tx=${out.proof_tx} incoming_sig=${incoming.detail}`);
  return send(res, 200, out);
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
        proofs: 'none — decisions are returned WITHOUT a Groth16 proof (see README: scoring caveat, -2 per provable task, reliability bonus forfeited)',
        seen_proofs: seen.size,
      });
    }
    if (req.method === 'POST' && (url === '/' || url === '/task')) {
      return handleTask(req, res);
    }
    return send(res, 404, { decision: 'REJECT', reason_code: 'VK_SUBSTITUTION', proof_tx: null });
  } catch (e) {
    console.error(`[gatecheck] ERROR ${req.method} ${req.url}: ${e.message}`);
    return send(res, 200, { decision: 'REJECT', reason_code: 'VK_SUBSTITUTION', proof_tx: null });
  }
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`GateCheck listening on ${PORT} (signed=${Boolean(HMAC_SECRET)}, seen=${seen.size})`);
});
