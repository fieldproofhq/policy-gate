/**
 * Fieldproof Policy Gate — reference API server v0.1
 * Zero dependencies. Node >= 18.  Run: node server.js  (PORT env, default 8402)
 *
 * POST /v1/check
 *   body: { "request": { "action": "...", "actor": "...", "params": {...} },
 *           "policy": {...} }            // inline policy, OR
 *          { "request": {...}, "policy_id": "default-action-tiers" }   // built-in
 *   -> 200 { decision, matched_rule, tier, tier_label, rationale, ... }
 *
 * GET /v1/policies            -> list built-in policy ids
 * GET /healthz                -> ok
 *
 * ---- x402 PAYMENT WIRING (not active in v0.1) --------------------------------
 * Production plan: front /v1/check with x402 so agents pay per call in USDC on
 * Base ($0.005/check). With the express stack this is ~6 lines:
 *
 *   const { paymentMiddleware } = require('x402-express');
 *   app.use(paymentMiddleware(
 *     RECEIVING_WALLET_ADDRESS,                    // <-- HUMAN GATE: owner creates
 *     { 'POST /v1/check': { price: '$0.005', network: 'base' } },
 *     { url: 'https://x402.org/facilitator' }      // Coinbase facilitator
 *   ));
 *
 * Until a receiving wallet exists (human-gated: wallet creation = account
 * creation), the server runs in FREE_MODE and adds an X-Fieldproof-Free header
 * so early adopters know payment is coming.
 * -----------------------------------------------------------------------------
 */

'use strict';

const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const { check } = require('./policy-engine.js');

const PORT = process.env.PORT || 8402;
const POLICY_DIR = path.join(__dirname, 'policies');
const MAX_BODY = 64 * 1024; // 64 KiB — policies are small by design

function loadBuiltinPolicies() {
  const map = {};
  for (const f of fs.readdirSync(POLICY_DIR)) {
    if (f.endsWith('.json')) {
      map[f.replace(/\.json$/, '')] = JSON.parse(fs.readFileSync(path.join(POLICY_DIR, f), 'utf8'));
    }
  }
  return map;
}
const BUILTINS = loadBuiltinPolicies();

function json(res, code, obj) {
  const body = JSON.stringify(obj, null, 2);
  res.writeHead(code, {
    'content-type': 'application/json',
    'x-fieldproof-free': 'true; x402 pricing coming - follow @FieldProofAI',
  });
  res.end(body);
}

const server = http.createServer((req, res) => {
  if (req.method === 'GET' && req.url === '/healthz') return json(res, 200, { ok: true });
  if (req.method === 'GET' && req.url === '/v1/policies') {
    return json(res, 200, { policies: Object.keys(BUILTINS) });
  }
  if (req.method === 'POST' && req.url === '/v1/check') {
    let body = '';
    let overflow = false;
    req.on('data', (c) => {
      body += c;
      if (body.length > MAX_BODY) { overflow = true; req.destroy(); }
    });
    req.on('close', () => { if (overflow) { /* destroyed */ } });
    req.on('end', () => {
      let parsed;
      try {
        parsed = JSON.parse(body);
      } catch {
        return json(res, 400, { error: 'invalid_json' });
      }
      const policy = parsed.policy || BUILTINS[parsed.policy_id];
      if (!policy) return json(res, 400, { error: 'no_policy', hint: 'send "policy" inline or a known "policy_id"; GET /v1/policies lists built-ins' });
      const verdict = check(policy, parsed.request);
      if (verdict.error) return json(res, 422, verdict);
      return json(res, 200, verdict);
    });
    return;
  }
  json(res, 404, { error: 'not_found', endpoints: ['POST /v1/check', 'GET /v1/policies', 'GET /healthz'] });
});

if (require.main === module) {
  server.listen(PORT, () => console.log(`policy-gate listening on :${PORT} (FREE_MODE — x402 wiring pending wallet)`));
}
module.exports = { server };
