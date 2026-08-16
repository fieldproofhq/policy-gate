// Test harness: engine cases + HTTP handler (free mode + paid 402 shape).
// Run: node test-worker.mjs   (Node >= 18; uses global Request/Response)
import assert from 'node:assert';
import worker, { check, globMatch, DEFAULT_POLICY, assessReceived, satsForGoal } from './worker.js';

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
assert.match(pack.url, /\/v1\/pay\/pack/);
res = await call(freeEnv, 'GET', '/v1/pay/pack');
assert.strictEqual(res.status, 200);
assert.match(res.headers.get('content-type'), /text\/html/);
const packPage = await res.text();
assert.match(packPage, /\$59/);
assert.match(packPage, /agentic-ai-governance-pack\?wanted=true/);
res = await call(freeEnv, 'GET', '/v1/pay/cmo');
assert.strictEqual(res.status, 200);
assert.match(res.headers.get('content-type'), /text\/html/);
const cmoPage = await res.text();
assert.match(cmoPage, /\$39/);
assert.match(cmoPage, /fractional-cmo-launch-kit\?wanted=true/);
assert.match(cmoPage, /does not meet/);
res = await call(freeEnv, 'GET', '/v1/pay');
assert.strictEqual(res.status, 200);
assert.match(res.headers.get('content-type'), /text\/html/);
const payIndex = await res.text();
assert.match(payIndex, /Pay Fieldproof \$42/);
assert.match(payIndex, /\/v1\/pay\/pack/);
assert.match(payIndex, /\/v1\/pay\/cmo/);
assert.match(payIndex, /\/v1\/pay\/tip-jar/);
assert.match(payIndex, /\/v1\/pay\/usdc/);
assert.match(payIndex, /\/v1\/pay\/btc/);
assert.match(payIndex, /\/v1\/pay\/zelle/);
assert.match(payIndex, /\/v1\/pay\/x402/);
assert.match(payIndex, /\/v1\/sponsor/);
res = await call(freeEnv, 'GET', '/v1/checkouts');
assert.strictEqual(res.status, 200);
const listed = await res.json();
const tipLive = listed.checkouts.find((o) => o.id === 'tip-jar');
assert.match(tipLive.url, /tip-jar/);
assert.equal(tipLive.amount_usd, 42);
assert.equal(tipLive.meets_first_42, true);
const indexOffer = listed.checkouts.find((o) => o.id === 'pay-index');
assert.match(indexOffer.url, /\/v1\/pay$/);
assert.equal(indexOffer.meets_first_42, false);
const cmo = listed.checkouts.find((o) => o.id === 'cmo-kit');
assert.equal(cmo.amount_usd, 39);
assert.equal(cmo.meets_first_42, false);
assert.match(cmo.url, /\/v1\/pay\/cmo/);
const tip42 = listed.checkouts.find((o) => o.id === 'tip-jar-42');
assert.equal(tip42.amount_usd, 42);
assert.equal(tip42.meets_first_42, true);
assert.match(tip42.url, /\/v1\/pay\/tip-jar/);
res = await call(freeEnv, 'GET', '/v1/pay/tip-jar');
assert.strictEqual(res.status, 200);
assert.match(res.headers.get('content-type'), /text\/html/);
const tipPage = await res.text();
assert.match(tipPage, /\$42/);
assert.match(tipPage, /tip-jar\?wanted=true/);
const x402 = listed.checkouts.find((o) => o.id === 'x402-check');
assert.match(x402.url, /\/v1\/pay\/x402/);
assert.equal(x402.checks_for_42, 8400);
res = await call({ PAY_TO: '0x07C2383008a9ed30581f27Db5531E19411c94fb3', PRICE_USD: '0.005' }, 'GET', '/v1/pay/x402');
assert.strictEqual(res.status, 200);
assert.match(res.headers.get('content-type'), /text\/html/);
const x402Page = await res.text();
assert.match(x402Page, /0\.005/);
assert.match(x402Page, /8400/);
assert.match(x402Page, /POST \/v1\/check/);
const sponsorOffer = listed.checkouts.find((o) => o.id === 'x402-sponsor-42');
assert.equal(sponsorOffer.amount_usd, 42);
assert.equal(sponsorOffer.meets_first_42, true);
assert.match(sponsorOffer.url, /\/v1\/sponsor$/);
const sponsorEnv = { PAY_TO: '0x07C2383008a9ed30581f27Db5531E19411c94fb3', PRICE_USD: '0.005' };
res = await call(sponsorEnv, 'GET', '/v1/sponsor');
assert.strictEqual(res.status, 200);
const sponsorDocs = await res.json();
assert.equal(sponsorDocs.price_usd, 42);
assert.equal(sponsorDocs.amount_atomic, '42000000');
assert.equal(sponsorDocs.accepts[0].maxAmountRequired, '42000000');
res = await call(sponsorEnv, 'POST', '/v1/sponsor');
assert.strictEqual(res.status, 402);
const sponsor402 = await res.json();
assert.equal(sponsor402.accepts[0].maxAmountRequired, '42000000');
assert.notEqual(sponsor402.accepts[0].maxAmountRequired, '5000');
res = await call(sponsorEnv, 'GET', '/.well-known/x402');
const discovered = await res.json();
assert.ok(discovered.resources.some((item) => item.url.endsWith('/v1/sponsor') && item.accepts[0].amount === '42000000'));
const usdc = listed.checkouts.find((o) => o.id === 'usdc-direct');
assert.equal(usdc.amount_usd, 42);
assert.equal(usdc.meets_first_42, true);
assert.match(usdc.pay_uri, /uint256=42000000/);
assert.match(usdc.qr_url, /create-qr-code/);
assert.match(usdc.qr_url, /uint256%3D42000000/);
assert.match(usdc.url, /\/v1\/pay\/usdc/);
res = await call({ PAY_TO: '0x07C2383008a9ed30581f27Db5531E19411c94fb3' }, 'GET', '/v1/pay/usdc');
assert.strictEqual(res.status, 200);
assert.match(res.headers.get('content-type'), /text\/html/);
const payPage = await res.text();
assert.match(payPage, /42 USDC/);
assert.match(payPage, /0x07C2383008a9ed30581f27Db5531E19411c94fb3/);
assert.match(payPage, /ethereum:0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913@8453\/transfer/);
assert.match(payPage, /create-qr-code/);
assert.match(payPage, /uint256%3D42000000/);
const zelle = listed.checkouts.find((o) => o.id === 'zelle');
assert.equal(zelle.amount_usd, 42);
assert.equal(zelle.meets_first_42, true);
assert.match(zelle.pay_to, /3labsio@gmail.com/);
assert.match(zelle.url, /\/v1\/pay\/zelle/);
res = await call(freeEnv, 'GET', '/v1/pay/zelle');
assert.strictEqual(res.status, 200);
assert.match(res.headers.get('content-type'), /text\/html/);
const zellePage = await res.text();
assert.match(zellePage, /\$42/);
assert.match(zellePage, /3labsio@gmail.com/);
assert.match(zellePage, /Fieldproof/);
const btc = listed.checkouts.find((o) => o.id === 'bitcoin');
assert.match(btc.pay_to, /^bc1q/);
assert.match(btc.url, /\/v1\/pay\/btc/);
assert.equal(satsForGoal(63000, 42), 66667);
res = await call(freeEnv, 'GET', '/v1/pay/btc');
assert.strictEqual(res.status, 200);
assert.match(res.headers.get('content-type'), /text\/html/);
const btcPage = await res.text();
assert.match(btcPage, /bitcoin:bc1q/);
assert.match(btcPage, /bc1qxwjhlllya7yvh0kvfggrjfzxwme7zhqs07777t/);

const selfTest = assessReceived(0.005, '2026-08-16T06:30:00.000Z');
assert.equal(selfTest.externalUsd, 0);
assert.equal(selfTest.goalMet, false);
assert.equal(selfTest.remainingUsd, 42);
const met = assessReceived(42.005, '2026-08-16T06:30:00.000Z');
assert.equal(met.externalUsd, 42);
assert.equal(met.goalMet, true);

const realFetch = globalThis.fetch;
globalThis.fetch = async (url, init) => {
  const href = String(url);
  if (/mainnet\.base\.org|base\.publicnode\.com|1rpc\.io\/base/.test(href)) {
    const payload = JSON.parse(init.body);
    assert.equal(payload.method, 'eth_call');
    return { json: async () => ({ result: '0x' + BigInt(5000).toString(16) }) };
  }
  if (href.includes('/api/v1/prices')) return { json: async () => ({ USD: 63000 }) };
  if (href.includes('/api/address/')) {
    return { json: async () => ({ chain_stats: { funded_txo_sum: 0, spent_txo_sum: 0 }, mempool_stats: { funded_txo_sum: 0 } }) };
  }
  throw new Error('unexpected fetch ' + href);
};
try {
  const receiveEnv = { PAY_TO: '0x07C2383008a9ed30581f27Db5531E19411c94fb3', NETWORK: 'eip155:8453' };
  res = await call(receiveEnv, 'GET', '/v1/received');
  assert.strictEqual(res.status, 200, 'received is free and public');
  const received = await res.json();
  assert.equal(received.externalUsd, 0);
  assert.equal(received.goalMet, false);
  assert.equal(received.selfTestUsd, 0.005);
  assert.equal(received.sources.btcUsd, 0);
  assert.equal(received.bitcoin.sats, 0);
  const quoted = received.checkouts.find((o) => o.id === 'bitcoin');
  assert.equal(quoted.amount_sats, 66667);
  assert.equal(quoted.meets_first_42, true);
  assert.ok(received.checkouts.some((o) => o.id === 'usdc-direct' && o.meets_first_42));
} finally {
  globalThis.fetch = realFetch;
}
res = await call(freeEnv, 'GET', '/v1/received');
assert.strictEqual(res.status, 200);
assert.equal((await res.json()).status, 'unavailable');

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

/* 4c — discoverability. A directory rejected this service on 2026-08-16 with
   "no /.well-known/x402 and no 402 challenge from endpoint", because probers GET and GET
   used to 404. Both paths are now asserted so the service cannot go invisible again. */
res = await call(paidEnv, 'GET', '/.well-known/x402');
assert.strictEqual(res.status, 200, 'discovery manifest must be served');
const wk = await res.json();
assert.strictEqual(wk.x402Version, 2);
assert.ok(wk.resources?.length >= 1, 'manifest lists at least one resource');
assert.ok(wk.resources[0].url.endsWith('/v1/check'), 'manifest points at the paid route');
assert.strictEqual(wk.resources[0].accepts[0].payTo, paidEnv.PAY_TO, 'manifest quotes the real payee');

res = await call(paidEnv, 'GET', '/v1/check');
assert.strictEqual(res.status, 200, 'GET documents the route; health probes read non-2xx as a dead service');
const getDocs = await res.json();
assert.strictEqual(getDocs.method, 'POST', 'docs name the paid method');
assert.ok(getDocs.accepts?.[0]?.payTo === paidEnv.PAY_TO, 'docs still carry the payment requirements');

/* 4d — MCP (Streamable HTTP). Discovery channel for agents that speak MCP rather than x402.
   The free tools must be genuinely useful and the paid one must NOT leak a verdict. */
async function mcp(env, method, params) {
  const res = await call(env, 'POST', '/mcp', { jsonrpc: '2.0', id: 1, method, params });
  if (res.status === 202) return { accepted: true };
  return res.json();
}

let m = await mcp(paidEnv, 'initialize', { protocolVersion: '2025-06-18' });
assert.strictEqual(m.result.serverInfo.name, 'fieldproof-policy-gate');
assert.ok(m.result.capabilities.tools, 'declares tool capability');

m = await mcp(paidEnv, 'tools/list');
const toolNames = m.result.tools.map((t) => t.name);
assert.deepStrictEqual(toolNames.sort(), ['first_42_sponsor', 'policy_check', 'policy_example', 'policy_rules']);
for (const t of m.result.tools) {
  assert.ok(t.description?.length > 20 && t.inputSchema, `${t.name} needs a description and schema`);
}

m = await mcp(paidEnv, 'tools/call', { name: 'policy_example' });
const mcpEx = JSON.parse(m.result.content[0].text);
assert.ok(mcpEx.examples.length >= 3, 'free example tool returns worked verdicts');
for (const e of mcpEx.examples) {
  assert.strictEqual(e.verdict.decision, check(DEFAULT_POLICY, e.request).decision, 'from the live engine');
}

/* the paid tool must quote a price, never answer */
m = await mcp(paidEnv, 'tools/call', {
  name: 'policy_check',
  arguments: { request: { action: 'payments.send', params: { amount_usd: 20 } } },
});
const quoted = JSON.parse(m.result.content[0].text);
assert.strictEqual(quoted.payment_required, true, 'paid tool must not answer for free');
assert.strictEqual(quoted.decision, undefined, 'MCP must not leak the verdict');
assert.strictEqual(quoted.accepts[0].payTo, paidEnv.PAY_TO, 'quotes the real payee');

m = await mcp(paidEnv, 'tools/call', { name: 'first_42_sponsor' });
const sponsorQuote = JSON.parse(m.result.content[0].text);
assert.equal(sponsorQuote.price_usd, 42);
assert.equal(sponsorQuote.amount_atomic, '42000000');
assert.match(sponsorQuote.endpoint, /\/v1\/sponsor$/);
assert.equal(sponsorQuote.accepts[0].maxAmountRequired, '42000000');
assert.notEqual(sponsorQuote.accepts[0].maxAmountRequired, '5000');

/* free mode is the one place it may answer */
m = await mcp(freeEnv, 'tools/call', { name: 'policy_check', arguments: { request: { action: 'gmail.read' } } });
assert.strictEqual(JSON.parse(m.result.content[0].text).decision, 'allow', 'free mode answers');

m = await mcp(paidEnv, 'tools/call', { name: 'no_such_tool' });
assert.strictEqual(m.error.code, -32602, 'unknown tool -> JSON-RPC error, not a crash');
m = await mcp(paidEnv, 'bogus/method');
assert.strictEqual(m.error.code, -32601, 'unknown method -> method not found');

/* 5 — CORS preflight */
res = await worker.fetch(new Request(base + '/v1/check', { method: 'OPTIONS' }), freeEnv);
assert.strictEqual(res.status, 204);
assert.ok(res.headers.get('access-control-allow-origin'));

console.log(`OK — ${pass} verdict cases + 5 engine checks + 13 HTTP checks passed`);
