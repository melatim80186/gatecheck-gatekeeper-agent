// GateCheck local test — spawns server.mjs on a test port with a test
// HMAC secret, runs the full trap matrix, verifies the response signature
// independently, then resets seen.json to [] and exits.
// Run:  npm test        (or: node test-local.mjs)
// No network, no keys, no deployment — everything is local.
import { spawn } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const DIR = path.dirname(fileURLToPath(import.meta.url));
const PORT = 18099;
const BASE = `http://127.0.0.1:${PORT}`;
const SECRET = 'test-secret-not-a-real-key';
const SEEN_FILE = path.join(DIR, 'seen.json');

let passed = 0;
let failed = 0;
function check(name, cond, extra = '') {
  if (cond) { passed++; console.log(`  PASS ${name}`); }
  else { failed++; console.log(`  FAIL ${name} ${extra}`); }
}

// Independent signature verification: HMAC-SHA256(secret, raw body).
async function verifySig(res, rawText) {
  const header = res.headers.get('x-agent-games-signature');
  if (!header || !header.startsWith('sha256=')) return false;
  const expected = crypto.createHmac('sha256', SECRET).update(Buffer.from(rawText, 'utf8')).digest('hex');
  return header === `sha256=${expected}`;
}

async function postTask(payload, { rawBody = null, signed = true } = {}) {
  const body = rawBody ?? JSON.stringify(payload);
  const headers = { 'content-type': 'application/json' };
  if (signed) {
    headers['x-agent-games-signature'] =
      'sha256=' + crypto.createHmac('sha256', SECRET).update(Buffer.from(body, 'utf8')).digest('hex');
  }
  const res = await fetch(`${BASE}/task`, { method: 'POST', headers, body });
  const text = await res.text();
  return { res, text, json: JSON.parse(text), sigOk: await verifySig(res, text) };
}

const VK = '0x7d3a00000000000000000000000000000000000000000000000000000000f291';
const RECIP = '0xDe4200000000000000000000000000000000009f01';

function baseTask(overrides = {}) {
  return {
    type: 'agent-games.proof-gatekeeper.v1',
    task_id: 'gk_test_1',
    mode: 'practice',
    issued_at: '2026-11-15T10:00:00Z',
    deadline_at: '2026-11-15T10:01:00Z',
    input: {
      registered_vk: VK,
      proof_vk: VK,
      minimum: '1000',
      public_balance: '1460',
      expiry_block: 19842201,
      current_block: 19832000,
      recipient: RECIP,
      condition_recipient: RECIP,
      amount: '500',
      max_transfer: '1000',
      proof_tx: '0xvalid00000000000000000000000000000000000000000000000000000001',
      ...overrides,
    },
  };
}

async function main() {
  const server = spawn('node', ['server.mjs'], {
    cwd: DIR,
    env: { ...process.env, PORT: String(PORT), AGENT_HMAC_SECRET: SECRET },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  server.stdout.on('data', (d) => process.stdout.write('[server] ' + d));
  server.stderr.on('data', (d) => process.stdout.write('[server:err] ' + d));

  try {
    // Wait for /health (up to 10 s).
    let healthy = false;
    for (let i = 0; i < 50 && !healthy; i++) {
      try {
        const r = await fetch(`${BASE}/health`);
        healthy = r.ok && (await r.json()).ok === true;
      } catch { await new Promise((r) => setTimeout(r, 200)); }
    }
    check('GET /health returns ok:true', healthy);
    const healthJson = await (await fetch(`${BASE}/health`)).json();
    check('GET /health returns protocolVersion v1', healthJson.protocolVersion === 'v1', JSON.stringify(healthJson));
    check('GET /health body is exactly protocol-v1 JSON', JSON.stringify(healthJson) === JSON.stringify({ ok: true, protocolVersion: 'v1' }), JSON.stringify(healthJson));

    // Platform preflight GETs the registered endpoint (root, or /agent) and
    // requires exactly {"ok":true,"protocolVersion":"v1"}, signed.
    const rootGetRes = await fetch(`${BASE}/`);
    const rootGetText = await rootGetRes.text();
    check('GET / returns exactly protocol-v1 JSON', rootGetText === JSON.stringify({ ok: true, protocolVersion: 'v1' }), rootGetText);
    check('GET / response is signed', await verifySig(rootGetRes, rootGetText));
    const agentGetRes = await fetch(`${BASE}/agent`);
    const agentGetText = await agentGetRes.text();
    check('GET /agent returns exactly protocol-v1 JSON', agentGetText === JSON.stringify({ ok: true, protocolVersion: 'v1' }), agentGetText);

    const cardRes = await fetch(`${BASE}/info`);
    const card = await cardRes.json();
    check('GET /info agent card is GateCheck', card.agent === 'GateCheck');
    check('GET /info card states no Groth16 proofs', typeof card.proofs === 'string' && card.proofs.includes('WITHOUT'));
    check('GET /info response is signed', await verifySig(cardRes, JSON.stringify(card)) || cardRes.headers.has('x-agent-games-signature'));

    // 1) Sample payload from the brief: VKs differ -> VK_SUBSTITUTION.
    const sample = baseTask({ proof_vk: '0xa4c100000000000000000000000000000000000000000000000000000000b8ff', proof_tx: '0xa4c1000000000000000000000000000000000000000000000000000000008ff1' });
    let r = await postTask(sample);
    check('sample payload -> REJECT VK_SUBSTITUTION', r.json.decision === 'REJECT' && r.json.reason_code === 'VK_SUBSTITUTION', JSON.stringify(r.json));
    check('sample echoes proof_tx', r.json.proof_tx === sample.input.proof_tx);
    check('task response is signed (x-agent-games-signature verifies)', r.sigOk);

    // 2) Fully valid variant -> APPROVE VALID_CONDITION.
    const valid = baseTask();
    r = await postTask(valid);
    check('valid payload -> APPROVE VALID_CONDITION', r.json.decision === 'APPROVE' && r.json.reason_code === 'VALID_CONDITION', JSON.stringify(r.json));

    // 3) Re-post the same valid payload -> PROOF_REUSED.
    r = await postTask(valid);
    check('re-post same proof_tx -> REJECT PROOF_REUSED', r.json.decision === 'REJECT' && r.json.reason_code === 'PROOF_REUSED', JSON.stringify(r.json));

    // seen.json on disk must contain the approved proof_tx.
    const seenOnDisk = JSON.parse(fs.readFileSync(SEEN_FILE, 'utf8'));
    check('seen.json persisted the approved proof_tx', seenOnDisk.includes(valid.input.proof_tx), JSON.stringify(seenOnDisk));

    // 4) Expired variant -> EXPIRED_CONDITION.
    r = await postTask(baseTask({ task_id: 'gk_test_exp', proof_tx: '0xexp1000000000000000000000000000000000000000000000000000000001', current_block: 19842202 }));
    check('expired variant -> REJECT EXPIRED_CONDITION', r.json.decision === 'REJECT' && r.json.reason_code === 'EXPIRED_CONDITION', JSON.stringify(r.json));

    // 5) Threshold variant -> THRESHOLD_MISMATCH.
    r = await postTask(baseTask({ task_id: 'gk_test_thr', proof_tx: '0xthr1000000000000000000000000000000000000000000000000000000001', public_balance: '999' }));
    check('threshold variant -> REJECT THRESHOLD_MISMATCH', r.json.decision === 'REJECT' && r.json.reason_code === 'THRESHOLD_MISMATCH', JSON.stringify(r.json));

    // 6) Recipient variant -> RECIPIENT_MISMATCH.
    r = await postTask(baseTask({ task_id: 'gk_test_rec', proof_tx: '0xrec1000000000000000000000000000000000000000000000000000000001', condition_recipient: '0xBEEF00000000000000000000000000000000000001' }));
    check('recipient variant -> REJECT RECIPIENT_MISMATCH', r.json.decision === 'REJECT' && r.json.reason_code === 'RECIPIENT_MISMATCH', JSON.stringify(r.json));

    // 7) Amount variant -> AMOUNT_OVERFLOW.
    r = await postTask(baseTask({ task_id: 'gk_test_amt', proof_tx: '0xamt1000000000000000000000000000000000000000000000000000000001', amount: '1001' }));
    check('amount variant -> REJECT AMOUNT_OVERFLOW', r.json.decision === 'REJECT' && r.json.reason_code === 'AMOUNT_OVERFLOW', JSON.stringify(r.json));

    // 8) Case-insensitive recipient + huge BigInt values -> APPROVE.
    r = await postTask(baseTask({
      task_id: 'gk_test_big',
      proof_tx: '0xbig1000000000000000000000000000000000000000000000000000000001',
      recipient: RECIP.toUpperCase(),
      condition_recipient: RECIP.toLowerCase(),
      minimum: '1000000000000000000000000000000',
      public_balance: '1000000000000000000000000000001',
      amount: '999999999999999999999999999999',
      max_transfer: '1000000000000000000000000000000',
    }));
    check('case-insensitive recipient + >2^53 BigInts -> APPROVE', r.json.decision === 'APPROVE' && r.json.reason_code === 'VALID_CONDITION', JSON.stringify(r.json));

    // 9) Missing fields -> REJECT, no crash.
    r = await postTask({ type: 'agent-games.proof-gatekeeper.v1', task_id: 'gk_test_empty', input: {} });
    check('empty input -> REJECT VK_SUBSTITUTION (fail closed)', r.json.decision === 'REJECT' && r.json.reason_code === 'VK_SUBSTITUTION', JSON.stringify(r.json));
    r = await postTask({ task_id: 'gk_test_noinput' });
    check('missing input object -> REJECT, no crash', r.json.decision === 'REJECT', JSON.stringify(r.json));

    // 10) Malformed JSON -> REJECT decision, HTTP 200, no crash.
    r = await postTask(null, { rawBody: '{not json' });
    check('malformed JSON -> REJECT decision, no crash', r.res.status === 200 && r.json.decision === 'REJECT', `status=${r.res.status} ${r.text}`);

    // 11) Unsigned request (no incoming signature header) is still answered.
    r = await postTask(baseTask({ task_id: 'gk_test_unsigned', proof_tx: '0xuns1000000000000000000000000000000000000000000000000000000001' }), { signed: false });
    check('unsigned task still answered (pending dashboard confirmation)', r.json.decision === 'APPROVE', JSON.stringify(r.json));

    // 12) POST / (root) also accepts tasks.
    const rootRes = await fetch(`${BASE}/`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify(baseTask({ task_id: 'gk_test_root', proof_tx: '0xroo1000000000000000000000000000000000000000000000000000000001' })),
    });
    const rootJson = await rootRes.json();
    check('POST / accepts tasks', rootJson.decision === 'APPROVE' && rootJson.reason_code === 'VALID_CONDITION', JSON.stringify(rootJson));

    console.log(`\n${passed} passed, ${failed} failed`);
  } finally {
    server.kill('SIGTERM');
    // Reset seen.json so the shipped file starts clean.
    fs.writeFileSync(SEEN_FILE, '[]\n');
  }
  process.exit(failed ? 1 : 0);
}

main().catch((e) => { console.error(e); process.exit(1); });
