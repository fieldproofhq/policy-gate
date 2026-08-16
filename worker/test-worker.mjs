// Test harness: engine cases + HTTP handler (free mode + paid 402 shape).
// Run: node test-worker.mjs   (Node >= 18; uses global Request/Response)
import assert from 'node:assert';
import worker, { check, globMatch, DEFAULT_POLICY } from './worker.js';

const policy = DEFAULT_POLICY;

/* 1 — engine verdict cases (same 12 as v0.1 test.js) */
const cases = [
  [{ action: 'gmail.read' }, 'allow', 'read-anything'],
  [{ action: 'products.list' }, 'allow', 'list-search'],
  [{ action: 'payments.send', params: { amount_usd: 25 } }, 'require_approval', 'small-payments-need-approval'],
  [{ action: 'payments.send', params: { amount_usd: 51 } }, 'deny', 'large-payments-forbidden'],
  [{ action: 'payments.send' }, 'deny', 'payments-unknown-amount'],
  [{ action: 'files.delete' }, 'deny', 'no-deletes'],
  [{ action: 'crm.contacts.delete' }, 'deny', 'no-deletes'],
  [{ action: 'auth.password.reset' }, 'deny', 'no-credentials'],
  [{ action: 'content.update' }, 'allow', 'content-updates-ok'],
  [{ action: 'messages.send', params: { prior_contact: false } }, 'require_approval', 'outbound-messages-first-contact'],
  [{ action: 'messages.send', params: { prior_contact: true } }, 'allow', 'outbound-messages-known-thread'],
  [{ action: 'something.unheard.of' }, 'deny', null],
];
let pass = 0;
for (const [req, wantDecision, wantRule] of cases) {
  const v = check(policy, req);
  assert.strictEqual(v.decision, wantDecision, `${req.action}: got ${v.decision}, want ${wantDecision}`);
  assert.strictEqual(v.matched_rule, wantRule, `${req.action}: matched ${v.matched_rule}, want ${wantRule}`);
  pass++;
}

/* 2 — engine hygiene */
assert.ok(globMatch('*.read', 'a.read') && !globMatch('*.read', 'a.b.read'), 'single-star scoping');
assert.ok(globMatch('**.delete', 'a.b.delete'), 'double-star spans segments');
assert.strictEqual(check(policy, { action: '' }).error, 'invalid_request');
assert.strictEqual(check({ default: 'nope' }, { action: 'x' }).error, 'invalid_policy');
const a = JSON.stringify(check(policy, { action: 'payments.send', params: { amount_usd: 25 } }));
const b = JSON.stringify(check(policy, { action: 'payments.send', params: { amount_usd: 25 } }));
assert.strictEqual(a, b, 'deterministic');

/* 3 — HTTP handler, FREE mode */
const freeEnv = {};
const base = 'https://policy-gate.example.workers.dev';
async function call(env, method, path, body, headers = {}) {
  const req = new Request(base + path, {
    method,
    headers: { 'content-type': 'application/json', ...headers },
    body: body ? JSON.stringify(body) : undefined,
  });
  return worker.fetch(req, env);
}

let res = await call(freeEnv, 'GET', '/healthz');
assert.strictEqual(res.status, 200);
assert.ok(res.headers.get('x-fieldproof-free'), 'free header present');

res = await call(freeEnv, 'GET', '/');
assert.strictEqual(res.status, 200);
let info = await res.json();
assert.strictEqual(info.pricing.mode, 'free');
assert.ok(Array.isArray(info.checkouts));
const pack = info.checkouts.find((o) => o.id === 'governance-pack');
assert.equal(pack.amount_usd, 59);
assert.equal(pack.meets_first_42, true);
assert.match(pack.url, /agentic-ai-governance-pack/);
res = await call(freeEnv, 'GET', '/v1/checkouts');
assert.strictEqual(res.status, 200);
const listed = await res.json();
assert.ok(listed.checkouts.some((o) => o.id === 'tip-jar' && o.url.includes('tip-jar')));

res = await call(freeEnv, 'GET', '/v1/policies');
assert.deepStrictEqual((await res.json()).policies, ['default-action-tiers']);

res = await call(freeEnv, 'POST', '/v1/check', {
  request: { action: 'payments.send', params: { amount_usd: 25 } },
  policy_id: 'default-action-tiers',
});
assert.strictEqual(res.status, 200);
let verdict = await res.json();
assert.strictEqual(verdict.decision, 'require_approval');

res = await call(freeEnv, 'POST', '/v1/check', { request: { action: 'x.read' } });
assert.strictEqual(res.status, 400, 'no policy -> 400');

res = await call(freeEnv, 'POST', '/v1/check', { request: { action: '' }, policy_id: 'default-action-tiers' });
assert.strictEqual(res.status, 422, 'invalid request -> 422');

/* 4 — HTTP handler, PAID mode: 402 shape (x402 v2 header + v1 body) */
const paidEnv = { PAY_TO: '0x000000000000000000000000000000000000dEaD', NETWORK: 'eip155:84532' };
res = await call(paidEnv, 'POST', '/v1/check', {
  request: { action: 'gmail.read' },
  policy_id: 'default-action-tiers',
});
assert.strictEqual(res.status, 402, 'paid mode without payment header -> 402');
const v1body = await res.json();
assert.strictEqual(v1body.x402Version, 1, 'v1-compatible body');
assert.strictEqual(v1body.accepts[0].payTo, paidEnv.PAY_TO);
assert.strictEqual(v1body.accepts[0].maxAmountRequired, '5000', 'v1 amount field ($0.005 = 5000 atomic)');
assert.strictEqual(v1body.accepts[0].amount, undefined, 'v1 body must NOT carry v2 amount field');
assert.strictEqual(v1body.accepts[0].network, 'base-sepolia', 'v1 uses network NAME');
assert.strictEqual(typeof v1body.accepts[0].resource, 'string', 'v1 requires resource url');
assert.strictEqual(v1body.accepts[0].mimeType, 'application/json', 'v1 requires mimeType');
const prHeader = res.headers.get('PAYMENT-REQUIRED');
assert.ok(prHeader, 'v2 PAYMENT-REQUIRED header present');
const v2 = JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(prHeader), (ch) => ch.charCodeAt(0))));
assert.strictEqual(v2.x402Version, 2);
assert.strictEqual(v2.accepts[0].network, 'eip155:84532', 'v2 uses CAIP-2');
assert.strictEqual(v2.accepts[0].amount, '5000', 'v2 amount field');
assert.strictEqual(v2.accepts[0].maxAmountRequired, undefined, 'v2 must NOT carry v1 maxAmountRequired');
assert.strictEqual(v2.accepts[0].resource, undefined, 'v2 reqs must NOT carry resource');
assert.strictEqual(v2.accepts[0].asset, '0x036CbD53842c5426634e7929541eC2318f3dCF7e', 'sepolia USDC');
assert.ok(v2.extensions.bazaar, 'bazaar discovery extension present');
assert.ok(v2.resource.serviceName === 'Fieldproof Policy Gate');

/* free-mode paths on paid env stay free */
res = await call(paidEnv, 'GET', '/healthz');
assert.strictEqual(res.status, 200, 'healthz never paywalled');
res = await call(paidEnv, 'GET', '/v1/policies');
assert.strictEqual(res.status, 200, 'policies list never paywalled');

/* malformed payment header -> 402 again, not 500 */
res = await call(paidEnv, 'POST', '/v1/check', { request: { action: 'x.read' } }, { 'x-payment': '!!!notbase64!!!' });
assert.strictEqual(res.status, 402, 'malformed payment -> 402');

/* 4b — the free evaluation surface. A buyer must be able to see what a verdict is and
   what it is grounded in BEFORE paying, or there is nothing to decide on. */
res = await call(paidEnv, 'GET', '/v1/example');
assert.strictEqual(res.status, 200, 'worked examples never paywalled');
const ex = await res.json();
assert.ok(Array.isArray(ex.examples) && ex.examples.length >= 5, 'several worked examples');
for (const e of ex.examples) {
  assert.ok(e.request && e.verdict, 'each example shows input and verdict');
  assert.ok(['allow', 'require_approval', 'deny'].includes(e.verdict.decision), 'real decision');
}
/* the examples must come from the live engine, not a hand-written copy that can drift */
for (const e of ex.examples) {
  const live = check(DEFAULT_POLICY, e.request);
  assert.strictEqual(e.verdict.decision, live.decision, `${e.label}: example drifted from the engine`);
  assert.strictEqual(e.verdict.matched_rule, live.matched_rule, `${e.label}: rule drifted from the engine`);
}
/* and they must cover the full decision range, or they are advertising rather than showing */
const decisions = new Set(ex.examples.map((e) => e.verdict.decision));
assert.ok(decisions.has('allow') && decisions.has('require_approval') && decisions.has('deny'),
  'examples must include a denial, not only happy paths');

/* bring-your-own-policy: the buyer's real question is whether they can express THEIR rules.
   The demo must use a policy that is genuinely not ours — different default included — or it
   proves nothing. */
const byo = ex.bring_your_own_policy;
assert.ok(byo && byo.policy && Array.isArray(byo.results), 'bring-your-own demo present');
assert.notStrictEqual(byo.policy.default, DEFAULT_POLICY.default, 'demo policy must differ from ours, default included');
assert.ok(byo.results.length >= 3, 'several outcomes shown');
for (const r of byo.results) {
  const live = check(byo.policy, r.request);
  assert.strictEqual(r.verdict.decision, live.decision, 'byo verdict computed by the live engine');
}
/* and it must show the custom default actually applying, not just matched rules */
assert.ok(byo.results.some((r) => r.verdict.default_applied === true), 'the custom default must be demonstrated');

res = await call(paidEnv, 'GET', '/v1/policies');
const pol = await res.json();
assert.ok(pol.definitions, 'policy definitions are public, not just ids');
assert.ok(pol.definitions['default-action-tiers'].rules.length >= 10, 'full ruleset exposed');

/* the paywall itself must not have moved */
res = await call(paidEnv, 'POST', '/v1/check', { policy_id: 'default-action-tiers', request: { action: 'x.read' } });
assert.strictEqual(res.status, 402, 'the product itself is still paid');

/* 5 — CORS preflight */
res = await worker.fetch(new Request(base + '/v1/check', { method: 'OPTIONS' }), freeEnv);
assert.strictEqual(res.status, 204);
assert.ok(res.headers.get('access-control-allow-origin'));

console.log(`OK — ${pass} verdict cases + 5 engine checks + 13 HTTP checks passed`);
