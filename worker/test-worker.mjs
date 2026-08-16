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
assert.equal(pack.amount_usd, 42);
assert.equal(pack.meets_first_42, true);
assert.match(pack.url, /\/v1\/pay\/pack/);
const stripeLink = info.checkouts.find((o) => o.id === 'stripe-payment-link');
assert.equal(stripeLink.amount_usd, 42);
assert.equal(stripeLink.meets_first_42, true);
assert.equal(stripeLink.url, 'https://buy.stripe.com/eVq4gA91U3Rr1Yt6z31sQ00');
assert.equal(info.card, 'https://buy.stripe.com/eVq4gA91U3Rr1Yt6z31sQ00');
assert.equal(info.fallback.url, info.card);
assert.match(res.headers.get('link') || '', /rel="payment"/);
res = await call(freeEnv, 'GET', '/v1/pay/card');
assert.strictEqual(res.status, 200);
assert.match(res.headers.get('content-type'), /text\/html/);
const cardPage = await res.text();
assert.match(cardPage, /Pay \$42 with card/);
assert.match(cardPage, /buy\.stripe\.com\/eVq4gA91U3Rr1Yt6z31sQ00/);
assert.match(cardPage, /Cash App/);
assert.match(cardPage, /US bank debit/);
assert.match(cardPage, /Klarna/);
assert.match(cardPage, /Afterpay/);
assert.match(cardPage, /Affirm/);
res = await call(freeEnv, 'GET', '/pay');
assert.strictEqual(res.status, 302);
assert.equal(res.headers.get('location'), 'https://buy.stripe.com/eVq4gA91U3Rr1Yt6z31sQ00');
res = await call(freeEnv, 'GET', '/v1/offer', undefined, { accept: 'text/html' });
assert.strictEqual(res.status, 302);
assert.equal(res.headers.get('location'), 'https://buy.stripe.com/eVq4gA91U3Rr1Yt6z31sQ00');
res = await call(freeEnv, 'GET', '/v1/offer');
assert.strictEqual(res.status, 200);
const freeOffer = await res.json();
assert.equal(freeOffer.price_usd, 42);
assert.equal(freeOffer.fallback.url, 'https://buy.stripe.com/eVq4gA91U3Rr1Yt6z31sQ00');
assert.match(res.headers.get('link') || '', /rel="payment"/);
res = await call(freeEnv, 'GET', '/robots.txt');
assert.strictEqual(res.status, 200);
assert.match(res.headers.get('content-type') || '', /text\/plain/);
const robots = await res.text();
assert.match(robots, /Sitemap: https:\/\/policy-gate\.example\.workers\.dev\/sitemap\.xml/);
assert.match(robots, /Allow: \//);
assert.match(res.headers.get('link') || '', /rel="payment"/);
res = await call(freeEnv, 'GET', '/sitemap.xml');
assert.strictEqual(res.status, 200);
assert.match(res.headers.get('content-type') || '', /xml/);
const sitemap = await res.text();
assert.match(sitemap, /\/pay<\/loc>/);
assert.match(sitemap, /\/v1\/sponsor<\/loc>/);
assert.match(sitemap, /\/mcp<\/loc>/);
assert.match(sitemap, /buy\.stripe\.com\/eVq4gA91U3Rr1Yt6z31sQ00/);
res = await call(freeEnv, 'GET', '/llms.txt');
assert.strictEqual(res.status, 200);
assert.match(await res.text(), /buy\.stripe\.com\/eVq4gA91U3Rr1Yt6z31sQ00/);
assert.match(await (await call(freeEnv, 'GET', '/llms.txt')).text(), /\/v1\/offer/);
res = await call(freeEnv, 'GET', '/.well-known/llms.txt');
assert.strictEqual(res.status, 200);
const wellKnownLlms = await res.text();
assert.match(wellKnownLlms, /buy\.stripe\.com\/eVq4gA91U3Rr1Yt6z31sQ00/);
assert.match(wellKnownLlms, /\/v1\/offer/);
assert.match(res.headers.get('link') || '', /rel="payment"/);
res = await call(freeEnv, 'GET', '/sitemap.xml');
assert.match(await res.text(), /\/\.well-known\/llms\.txt/);
res = await call(freeEnv, 'GET', '/llms-full.txt');
assert.strictEqual(res.status, 200);
const llmsFull = await res.text();
assert.match(llmsFull, /buy\.stripe\.com\/eVq4gA91U3Rr1Yt6z31sQ00/);
assert.match(llmsFull, /fieldproofhq\.github\.io\/offer\//);
assert.match(llmsFull, /\/v1\/offer/);
assert.match(llmsFull, /\/v1\/sponsor/);
assert.match(llmsFull, /3labsio@gmail.com/);
assert.match(res.headers.get('link') || '', /rel="payment"/);
res = await call(freeEnv, 'GET', '/.well-known/llms-full.txt');
assert.match(await res.text(), /buy\.stripe\.com\/eVq4gA91U3Rr1Yt6z31sQ00/);
res = await call(freeEnv, 'GET', '/sitemap.xml');
assert.match(await res.text(), /\/llms-full\.txt/);
res = await call(freeEnv, 'GET', '/.well-known/pay');
assert.strictEqual(res.status, 200);
const payDoc = await res.json();
assert.equal(payDoc.price_usd, 42);
assert.equal(payDoc.url, 'https://buy.stripe.com/eVq4gA91U3Rr1Yt6z31sQ00');
assert.ok(payDoc.methods.includes('affirm'));
assert.match(payDoc.short_url, /\/pay$/);
res = await call(freeEnv, 'GET', '/.well-known/agent-card.json');
assert.strictEqual(res.status, 200);
const card = await res.json();
assert.equal(card.name, 'Fieldproof Policy Gate');
assert.ok(card.skills.some((s) => s.id === 'pay-42'));
assert.equal(card.card, 'https://buy.stripe.com/eVq4gA91U3Rr1Yt6z31sQ00');
assert.equal(card.fallback.url, card.card);
assert.match(card.url, /\/mcp$/);
assert.match(res.headers.get('link') || '', /rel="payment"/);
res = await call(freeEnv, 'GET', '/.well-known/agent.json');
assert.equal((await res.json()).card, card.card);
res = await call(freeEnv, 'GET', '/sitemap.xml');
assert.match(await res.text(), /\/\.well-known\/agent-card\.json/);
res = await call(freeEnv, 'GET', '/openapi.json');
assert.strictEqual(res.status, 200);
const spec = await res.json();
assert.equal(spec.openapi, '3.1.0');
assert.ok(spec.paths['/v1/sponsor'].post);
assert.ok(spec.paths['/pay'].get);
assert.equal(spec.externalDocs.url, 'https://buy.stripe.com/eVq4gA91U3Rr1Yt6z31sQ00');
assert.equal(spec['x-payment'].url, spec.externalDocs.url);
assert.match(res.headers.get('link') || '', /rel="payment"/);
res = await call(freeEnv, 'GET', '/.well-known/openapi.json');
assert.equal((await res.json()).externalDocs.url, spec.externalDocs.url);
res = await call(freeEnv, 'GET', '/sitemap.xml');
assert.match(await res.text(), /\/openapi\.json/);
res = await call(freeEnv, 'GET', '/.well-known/ai-plugin.json');
assert.strictEqual(res.status, 200);
const plugin = await res.json();
assert.equal(plugin.schema_version, 'v1');
assert.equal(plugin.auth.type, 'none');
assert.match(plugin.api.url, /\/openapi\.json$/);
assert.equal(plugin['x-payment'].url, 'https://buy.stripe.com/eVq4gA91U3Rr1Yt6z31sQ00');
assert.match(res.headers.get('link') || '', /rel="payment"/);
res = await call(freeEnv, 'GET', '/sitemap.xml');
assert.match(await res.text(), /\/\.well-known\/ai-plugin\.json/);
res = await call(freeEnv, 'GET', '/.well-known/mcp.json');
assert.strictEqual(res.status, 200);
const mcpDoc = await res.json();
assert.equal(mcpDoc.transport, 'streamable-http');
assert.match(mcpDoc.url, /\/mcp$/);
assert.ok(mcpDoc.tools.includes('first_42_sponsor'));
assert.equal(mcpDoc.payment.url, 'https://buy.stripe.com/eVq4gA91U3Rr1Yt6z31sQ00');
assert.match(res.headers.get('link') || '', /rel="payment"/);
res = await call(freeEnv, 'GET', '/sitemap.xml');
assert.match(await res.text(), /\/\.well-known\/mcp\.json/);
assert.match(cardPage, /create-qr-code/);
assert.match(cardPage, /buy\.stripe\.com/);
assert.doesNotMatch(cardPage, /Mark gate/i);
res = await call(freeEnv, 'GET', '/', undefined, { accept: 'text/html' });
assert.strictEqual(res.status, 200);
assert.match(res.headers.get('content-type'), /text\/html/);
const homeHtml = await res.text();
assert.match(homeHtml, /Pay Fieldproof \$42/);
assert.match(homeHtml, /Browse the store/);
assert.match(homeHtml, /\$42 Governance Pack/);
assert.match(homeHtml, /\$42 with card/);
assert.match(homeHtml, /buy\.stripe\.com\/eVq4gA91U3Rr1Yt6z31sQ00/);
assert.doesNotMatch(homeHtml, /\$59/);
assert.doesNotMatch(homeHtml, /Self-buys do not count/i);
assert.match(homeHtml, /\/v1\/pay\/pack/);
assert.match(homeHtml, /\/v1\/sponsor/);
assert.doesNotMatch(homeHtml, /8400/);
assert.doesNotMatch(homeHtml, /does not meet/);
res = await call(freeEnv, 'GET', '/', undefined, { accept: 'application/json, text/html' });
assert.match((await res.json()).service, /Policy Gate/);
res = await call(freeEnv, 'GET', '/v1/pay/pack');
assert.strictEqual(res.status, 200);
assert.match(res.headers.get('content-type'), /text\/html/);
const packPage = await res.text();
assert.match(packPage, /\$42/);
assert.match(packPage, /agentic-ai-governance-pack\?wanted=true/);
assert.match(packPage, /public-files\.gumroad\.com\/k5vh8fw0i5jkr4pzz9zveemcfjax/);
assert.match(packPage, /Buy the \$42 pack/);
assert.match(packPage, /<img /);
assert.match(packPage, /gumroad\.com\/js\/gumroad\.js/);
assert.match(packPage, /gumroad-button/);
assert.match(packPage, /Pay \$42 with card/);
assert.match(packPage, /buy\.stripe\.com\/eVq4gA91U3Rr1Yt6z31sQ00/);
res = await call(freeEnv, 'GET', '/v1/pay/cmo');
assert.strictEqual(res.status, 200);
assert.match(res.headers.get('content-type'), /text\/html/);
const cmoPage = await res.text();
assert.match(cmoPage, /\$39/);
assert.match(cmoPage, /fractional-cmo-launch-kit\?wanted=true/);
assert.match(cmoPage, /public-files\.gumroad\.com\/q8ndyh3mpngn25hk15p4pwuby0my/);
assert.match(cmoPage, /<img /);
assert.match(cmoPage, /Buy the \$39 CMO kit/);
assert.match(cmoPage, /csuite\/cmo/);
assert.match(cmoPage, /gumroad\.com\/js\/gumroad\.js/);
assert.match(cmoPage, /gumroad-button/);
assert.match(cmoPage, /Pay \$42 with card/);
assert.match(cmoPage, /buy\.stripe\.com\/eVq4gA91U3Rr1Yt6z31sQ00/);
assert.doesNotMatch(cmoPage, /Self-buys do not count/i);
res = await call(freeEnv, 'GET', '/v1/pay');
assert.strictEqual(res.status, 200);
assert.match(res.headers.get('content-type'), /text\/html/);
const payIndex = await res.text();
assert.match(payIndex, /Pay Fieldproof \$42/);
assert.match(payIndex, /rel="payment"/);
assert.match(payIndex, /Card first/);
assert.match(payIndex, /\$42 tip jar/);
assert.match(payIndex, /\$42 Governance Pack/);
assert.match(payIndex, /store\.3labs\.io/);
assert.match(payIndex, /Browse the store/);
assert.match(payIndex, /fieldproofhq\.github\.io\/csuite/);
assert.doesNotMatch(payIndex, /Self-buys do not count/i);
assert.doesNotMatch(payIndex, /\$59 Governance Pack/);
assert.match(payIndex, /\/v1\/pay\/pack/);
assert.match(payIndex, /\/v1\/pay\/cmo/);
assert.match(payIndex, /\/v1\/pay\/tip-jar/);
assert.match(payIndex, /\/v1\/pay\/usdc/);
assert.match(payIndex, /\/v1\/pay\/btc/);
assert.match(payIndex, /\/v1\/pay\/zelle/);
assert.match(payIndex, /\/v1\/pay\/x402/);
assert.match(payIndex, /\/v1\/sponsor/);
assert.doesNotMatch(payIndex, /8400/);
assert.doesNotMatch(payIndex, /does not meet/);
res = await call(freeEnv, 'GET', '/v1/checkouts');
assert.strictEqual(res.status, 200);
const listed = await res.json();
assert.equal(listed.card, 'https://buy.stripe.com/eVq4gA91U3Rr1Yt6z31sQ00');
assert.equal(listed.fallback.url, listed.card);
assert.match(res.headers.get('link') || '', /rel="payment"/);
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
assert.match(tipPage, /store\.3labs\.io\/l\/tip-jar\?wanted=true/);
assert.match(tipPage, /public-files\.gumroad\.com\/5u12tofcw2kg35lga2na9ri6cba3/);
assert.match(tipPage, /<img /);
assert.match(tipPage, /gumroad\.com\/js\/gumroad\.js/);
assert.match(tipPage, /gumroad-button/);
assert.match(tipPage, /Pay \$42 with card/);
assert.match(tipPage, /buy\.stripe\.com\/eVq4gA91U3Rr1Yt6z31sQ00/);
assert.doesNotMatch(tipPage, /Self-buys|not income/i);
const x402 = listed.checkouts.find((o) => o.id === 'x402-check');
assert.match(x402.url, /\/v1\/pay\/x402/);
assert.equal(x402.checks_for_42, 8400);
res = await call({ PAY_TO: '0x07C2383008a9ed30581f27Db5531E19411c94fb3', PRICE_USD: '0.005' }, 'GET', '/v1/pay/x402');
assert.strictEqual(res.status, 200);
assert.match(res.headers.get('content-type'), /text\/html/);
const x402Page = await res.text();
assert.match(x402Page, /42 USDC/);
assert.match(x402Page, /\/v1\/sponsor/);
assert.match(x402Page, /0\.005/);
assert.match(x402Page, /8400/);
assert.match(x402Page, /POST \/v1\/check/);
assert.match(x402Page, /Pay \$42 with card/);
assert.match(x402Page, /buy\.stripe\.com\/eVq4gA91U3Rr1Yt6z31sQ00/);
const sponsorOffer = listed.checkouts.find((o) => o.id === 'x402-sponsor-42');
assert.equal(sponsorOffer.amount_usd, 42);
assert.equal(sponsorOffer.meets_first_42, true);
assert.match(sponsorOffer.url, /\/v1\/sponsor$/);
const offer42 = listed.checkouts.find((o) => o.id === 'offer-42');
assert.equal(offer42.amount_usd, 42);
assert.equal(offer42.meets_first_42, true);
assert.match(offer42.url, /\/v1\/offer$/);
const sponsorEnv = { PAY_TO: '0x07C2383008a9ed30581f27Db5531E19411c94fb3', PRICE_USD: '0.005' };
res = await call(sponsorEnv, 'GET', '/v1/offer');
assert.strictEqual(res.status, 402, 'GET /v1/offer quotes 42 USDC plus card fallback');
const offer402 = await res.json();
assert.equal(offer402.accepts[0].maxAmountRequired, '42000000');
assert.equal(offer402.fallback.url, 'https://buy.stripe.com/eVq4gA91U3Rr1Yt6z31sQ00');
assert.match(res.headers.get('link') || '', /rel="payment"/);
res = await call(sponsorEnv, 'POST', '/v1/offer');
assert.strictEqual(res.status, 402, 'POST /v1/offer quotes the same $42 path');
const offerPost = await res.json();
assert.equal(offerPost.accepts[0].maxAmountRequired, '42000000');
assert.equal(offerPost.fallback.url, offer402.fallback.url);
assert.match(res.headers.get('link') || '', /rel="payment"/);
res = await call(sponsorEnv, 'GET', '/v1/offer', undefined, { accept: 'text/html' });
assert.strictEqual(res.status, 302);
assert.equal(res.headers.get('location'), 'https://buy.stripe.com/eVq4gA91U3Rr1Yt6z31sQ00');
res = await call(sponsorEnv, 'GET', '/v1/sponsor');
assert.strictEqual(res.status, 402, 'GET /v1/sponsor without HTML Accept quotes 42 USDC plus card fallback');
const defaultSponsor = await res.json();
assert.equal(defaultSponsor.accepts[0].maxAmountRequired, '42000000');
assert.equal(defaultSponsor.fallback.url, 'https://buy.stripe.com/eVq4gA91U3Rr1Yt6z31sQ00');
assert.match(res.headers.get('link') || '', /rel="payment"/);
res = await call(sponsorEnv, 'GET', '/v1/sponsor', undefined, { accept: '*/*' });
assert.strictEqual(res.status, 402, 'generic Accept still quotes, not HTML');
res = await call(sponsorEnv, 'GET', '/v1/sponsor', undefined, { accept: 'application/json' });
assert.strictEqual(res.status, 402, 'unpaid GET /v1/sponsor with JSON Accept must quote');
const sponsorGet = await res.json();
assert.equal(sponsorGet.accepts[0].maxAmountRequired, '42000000');
assert.notEqual(sponsorGet.accepts[0].maxAmountRequired, '5000');
assert.equal(sponsorGet.fallback.url, 'https://buy.stripe.com/eVq4gA91U3Rr1Yt6z31sQ00');
assert.equal(sponsorGet.fallback.amountUsd, 42);
assert.ok(res.headers.get('payment-required'), 'JSON GET carries the v2 PAYMENT-REQUIRED header');
assert.match(res.headers.get('link') || '', /rel="payment"/);
assert.match(res.headers.get('link') || '', /buy\.stripe\.com\/eVq4gA91U3Rr1Yt6z31sQ00/);
res = await call(sponsorEnv, 'GET', '/v1/sponsor', undefined, { accept: 'text/html' });
assert.strictEqual(res.status, 200);
assert.match(res.headers.get('content-type'), /text\/html/);
const sponsorPage = await res.text();
assert.match(sponsorPage, /42 USDC/);
assert.match(sponsorPage, /uint256=42000000/);
assert.match(sponsorPage, /POST \/v1\/sponsor/);
assert.match(sponsorPage, /0x07C2383008a9ed30581f27Db5531E19411c94fb3/);
assert.match(sponsorPage, /Copy address/);
assert.match(sponsorPage, /Copy invoice/);
assert.match(sponsorPage, /navigator\.clipboard/);
assert.match(sponsorPage, /Pay 42 USDC in this browser/);
assert.match(sponsorPage, /eth_sendTransaction/);
assert.match(sponsorPage, /0xa9059cbb/);
assert.match(sponsorPage, /wallet_switchEthereumChain/);
assert.match(sponsorPage, /42000000/);
assert.doesNotMatch(sponsorPage, /private[_ ]?key/i);
res = await call(sponsorEnv, 'POST', '/v1/sponsor');
assert.strictEqual(res.status, 402);
const sponsor402 = await res.json();
assert.equal(sponsor402.accepts[0].maxAmountRequired, '42000000');
assert.notEqual(sponsor402.accepts[0].maxAmountRequired, '5000');
assert.equal(sponsor402.fallback.scheme, 'stripe');
assert.equal(sponsor402.fallback.url, 'https://buy.stripe.com/eVq4gA91U3Rr1Yt6z31sQ00');
assert.match(res.headers.get('link') || '', /rel="payment"/);
res = await call(sponsorEnv, 'GET', '/.well-known/x402');
const discovered = await res.json();
assert.ok(discovered.resources.some((item) => item.url.endsWith('/v1/sponsor') && item.accepts[0].amount === '42000000'));
assert.equal(discovered.fallback.url, 'https://buy.stripe.com/eVq4gA91U3Rr1Yt6z31sQ00');
assert.ok(discovered.resources.every((item) => item.fallback?.url === discovered.fallback.url));
assert.match(res.headers.get('link') || '', /rel="payment"/);
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
assert.match(payPage, /Copy address/);
assert.match(payPage, /Copy invoice/);
assert.match(payPage, /navigator\.clipboard/);
assert.match(payPage, /Pay 42 USDC in this browser/);
assert.match(payPage, /eth_sendTransaction/);
assert.match(payPage, /0xa9059cbb/);
assert.match(payPage, /wallet_switchEthereumChain/);
assert.doesNotMatch(payPage, /private[_ ]?key/i);
assert.match(payPage, /Pay \$42 with card/);
assert.match(payPage, /buy\.stripe\.com\/eVq4gA91U3Rr1Yt6z31sQ00/);
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
assert.match(zellePage, /mailto:3labsio@gmail.com/);
assert.match(zellePage, /Copy email/);
assert.match(zellePage, /Copy \$42/);
assert.match(zellePage, /navigator\.clipboard/);
assert.match(zellePage, /Pay \$42 with card/);
assert.match(zellePage, /buy\.stripe\.com\/eVq4gA91U3Rr1Yt6z31sQ00/);
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
assert.match(btcPage, /create-qr-code/);
assert.match(btcPage, /bitcoin%3Abc1q/);
assert.match(btcPage, /data-copy="bc1qxwjhlllya7yvh0kvfggrjfzxwme7zhqs07777t"/);
assert.match(btcPage, /Copy address/);
assert.match(btcPage, /Copy invoice/);
assert.match(btcPage, /navigator\.clipboard/);
assert.match(btcPage, /Pay \$42 with card/);
assert.match(btcPage, /buy\.stripe\.com\/eVq4gA91U3Rr1Yt6z31sQ00/);

res = await call({ PAY_TO: '0x07C2383008a9ed30581f27Db5531E19411c94fb3' }, 'GET', '/v1/pay/usdc.uri');
assert.strictEqual(res.status, 200);
assert.match(res.headers.get('content-type'), /text\/uri-list/);
assert.match(res.headers.get('link') || '', /rel="payment"/);
const usdcUri = await res.text();
assert.match(usdcUri, /^ethereum:0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913@8453\/transfer\?address=0x07C2383008a9ed30581f27Db5531E19411c94fb3&uint256=42000000\n?$/);
res = await call({ PAY_TO: '0x07C2383008a9ed30581f27Db5531E19411c94fb3' }, 'GET', '/v1/pay/usdc', undefined, { accept: 'text/uri-list' });
assert.match(res.headers.get('content-type'), /text\/uri-list/);
assert.match(await res.text(), /uint256=42000000/);
res = await call({ PAY_TO: '0x07C2383008a9ed30581f27Db5531E19411c94fb3' }, 'GET', '/v1/pay/usdc', undefined, { accept: 'application/json' });
assert.match(res.headers.get('content-type'), /application\/json/);
const usdcInvoice = await res.json();
assert.equal(usdcInvoice.scheme, 'eip681');
assert.equal(usdcInvoice.amountUsd, 42);
assert.match(usdcInvoice.uri, /uint256=42000000/);
assert.equal(usdcInvoice.card, 'https://buy.stripe.com/eVq4gA91U3Rr1Yt6z31sQ00');
res = await call(freeEnv, 'GET', '/v1/pay/btc.uri');
assert.strictEqual(res.status, 200);
assert.match(res.headers.get('content-type'), /text\/uri-list/);
assert.match(await res.text(), /^bitcoin:bc1qxwjhlllya7yvh0kvfggrjfzxwme7zhqs07777t/);
res = await call(freeEnv, 'GET', '/openapi.json');
assert.ok((await res.json()).paths['/v1/pay/usdc.uri'].get);
assert.ok((await (await call(freeEnv, 'GET', '/openapi.json')).json()).paths['/v1/pay/btc.uri'].get);
res = await call(freeEnv, 'GET', '/.well-known/pay');
const payManifest = await res.json();
assert.match(payManifest.also.usdc_uri, /\/v1\/pay\/usdc\.uri$/);
assert.match(payManifest.also.btc_uri, /\/v1\/pay\/btc\.uri$/);
assert.match(payManifest.also.invoice, /\/v1\/invoice$/);
res = await call({ PAY_TO: '0x07C2383008a9ed30581f27Db5531E19411c94fb3' }, 'GET', '/v1/invoice');
assert.strictEqual(res.status, 200);
assert.match(res.headers.get('content-type'), /application\/json/);
assert.match(res.headers.get('link') || '', /rel="payment"/);
const invoice = await res.json();
assert.equal(invoice.amountUsd, 42);
assert.equal(invoice.card, 'https://buy.stripe.com/eVq4gA91U3Rr1Yt6z31sQ00');
assert.ok(invoice.methods.some((m) => m.scheme === 'stripe' && m.url === invoice.card));
assert.ok(invoice.methods.some((m) => m.scheme === 'eip681' && /uint256=42000000/.test(m.uri)));
assert.ok(invoice.methods.some((m) => m.scheme === 'bip21' && /^bitcoin:bc1q/.test(m.uri)));
assert.ok(invoice.methods.some((m) => m.scheme === 'x402' && /\/v1\/sponsor$/.test(m.url)));
assert.ok(invoice.methods.some((m) => m.scheme === 'zelle' && m.payTo === '3labsio@gmail.com'));
res = await call(freeEnv, 'GET', '/v1/invoice', undefined, { accept: 'text/html' });
assert.strictEqual(res.status, 302);
assert.equal(res.headers.get('location'), 'https://buy.stripe.com/eVq4gA91U3Rr1Yt6z31sQ00');
res = await call(freeEnv, 'GET', '/.well-known/invoice.json');
assert.equal((await res.json()).id, 'fieldproof-42');
res = await call(freeEnv, 'GET', '/openapi.json');
assert.ok((await res.json()).paths['/v1/invoice'].get);
const listedInvoice = listed.checkouts.find((o) => o.id === 'invoice-42');
assert.equal(listedInvoice.amount_usd, 42);
assert.match(listedInvoice.url, /\/v1\/invoice$/);
res = await call(freeEnv, 'GET', '/v1/pay/card.uri');
assert.strictEqual(res.status, 200);
assert.match(res.headers.get('content-type'), /text\/uri-list/);
assert.match(res.headers.get('link') || '', /rel="payment"/);
assert.equal((await res.text()).trim(), 'https://buy.stripe.com/eVq4gA91U3Rr1Yt6z31sQ00');
res = await call(freeEnv, 'GET', '/v1/pay/card', undefined, { accept: 'text/uri-list' });
assert.match(res.headers.get('content-type'), /text\/uri-list/);
assert.match(await res.text(), /buy\.stripe\.com\/eVq4gA91U3Rr1Yt6z31sQ00/);
res = await call(freeEnv, 'GET', '/v1/pay/card', undefined, { accept: 'application/json' });
const cardInvoice = await res.json();
assert.equal(cardInvoice.scheme, 'stripe');
assert.equal(cardInvoice.amountUsd, 42);
assert.equal(cardInvoice.uri, 'https://buy.stripe.com/eVq4gA91U3Rr1Yt6z31sQ00');
assert.ok(cardInvoice.methods.includes('affirm'));
res = await call(freeEnv, 'GET', '/openapi.json');
assert.ok((await res.json()).paths['/v1/pay/card.uri'].get);
assert.match(payManifest.also.card_uri, /\/v1\/pay\/card\.uri$/);
const listedCardUri = listed.checkouts.find((o) => o.id === 'card-uri');
assert.equal(listedCardUri.amount_usd, 42);
assert.match(listedCardUri.url, /\/v1\/pay\/card\.uri$/);
assert.equal(listedCardUri.pay_uri, 'https://buy.stripe.com/eVq4gA91U3Rr1Yt6z31sQ00');
res = await call(freeEnv, 'GET', '/llms-full.txt');
assert.match(await res.text(), /\/v1\/pay\/card\.uri/);
res = await call(freeEnv, 'GET', '/sitemap.xml');
assert.match(await res.text(), /\/v1\/pay\/card\.uri/);
res = await call(freeEnv, 'GET', '/skills/pay/SKILL.md');
assert.strictEqual(res.status, 200);
assert.match(res.headers.get('content-type'), /text\/markdown/);
assert.match(res.headers.get('link') || '', /rel="payment"/);
const skill = await res.text();
assert.match(skill, /name: fieldproof-pay-42/);
assert.match(skill, /buy\.stripe\.com\/eVq4gA91U3Rr1Yt6z31sQ00/);
assert.match(skill, /\/v1\/pay\/card\.uri/);
assert.match(skill, /\/v1\/pay\/usdc\.uri/);
assert.match(skill, /\/v1\/invoice/);
assert.match(skill, /first_42_sponsor/);
assert.doesNotMatch(skill, /Self-buys do not count/i);
res = await call(freeEnv, 'GET', '/.well-known/skills.json');
const skillsDoc = await res.json();
assert.equal(skillsDoc.skills[0].amountUsd, 42);
assert.match(skillsDoc.skills[0].url, /\/skills\/pay\/SKILL\.md$/);
assert.equal(skillsDoc.skills[0].card, 'https://buy.stripe.com/eVq4gA91U3Rr1Yt6z31sQ00');
res = await call(freeEnv, 'GET', '/openapi.json');
assert.ok((await res.json()).paths['/skills/pay/SKILL.md'].get);
res = await call(freeEnv, 'GET', '/llms-full.txt');
assert.match(await res.text(), /\/skills\/pay\/SKILL\.md/);
res = await call(freeEnv, 'GET', '/sitemap.xml');
assert.match(await res.text(), /\/skills\/pay\/SKILL\.md/);
assert.match(payManifest.also.skill, /\/skills\/pay\/SKILL\.md$/);
res = await call(freeEnv, 'GET', '/package.json');
assert.strictEqual(res.status, 200);
assert.match(res.headers.get('link') || '', /rel="payment"/);
const npmPkg = await res.json();
assert.equal(npmPkg.name, '@fieldproofhq/policy-gate');
assert.ok(npmPkg.funding.some((item) => item.url === 'https://buy.stripe.com/eVq4gA91U3Rr1Yt6z31sQ00'));
assert.ok(npmPkg.funding.some((item) => /fieldproofhq\.github\.io\/offer\//.test(item.url)));
res = await call(freeEnv, 'GET', '/');
assert.ok((await res.json()).funding.some((item) => item.url === 'https://buy.stripe.com/eVq4gA91U3Rr1Yt6z31sQ00'));
res = await call(freeEnv, 'GET', '/.well-known/package.json');
assert.equal((await res.json()).funding[1].url, 'https://buy.stripe.com/eVq4gA91U3Rr1Yt6z31sQ00');
res = await call(freeEnv, 'GET', '/openapi.json');
assert.ok((await res.json()).paths['/package.json'].get);
res = await call(freeEnv, 'GET', '/llms-full.txt');
assert.match(await res.text(), /\/package\.json/);
res = await call(freeEnv, 'GET', '/sitemap.xml');
assert.match(await res.text(), /\/package\.json/);
assert.match(payManifest.also.funding, /\/package\.json$/);
res = await call(freeEnv, 'GET', '/v1/pay/zelle.uri');
assert.strictEqual(res.status, 200);
assert.match(res.headers.get('content-type'), /text\/uri-list/);
assert.match(res.headers.get('link') || '', /rel="payment"/);
const zelleUriBody = await res.text();
assert.match(zelleUriBody, /^mailto:3labsio@gmail.com\?subject=Fieldproof/);
assert.match(zelleUriBody, /Zelle/);
res = await call(freeEnv, 'GET', '/v1/pay/zelle', undefined, { accept: 'text/uri-list' });
assert.match(res.headers.get('content-type'), /text\/uri-list/);
assert.match(await res.text(), /^mailto:3labsio@gmail.com/);
res = await call(freeEnv, 'GET', '/v1/pay/zelle', undefined, { accept: 'application/json' });
const zelleInvoice = await res.json();
assert.equal(zelleInvoice.scheme, 'zelle');
assert.equal(zelleInvoice.amountUsd, 42);
assert.equal(zelleInvoice.payTo, '3labsio@gmail.com');
assert.match(zelleInvoice.uri, /^mailto:3labsio@gmail.com/);
res = await call(freeEnv, 'GET', '/openapi.json');
assert.ok((await res.json()).paths['/v1/pay/zelle.uri'].get);
assert.match(payManifest.also.zelle_uri, /\/v1\/pay\/zelle\.uri$/);
const listedZelleUri = listed.checkouts.find((o) => o.id === 'zelle-uri');
assert.equal(listedZelleUri.amount_usd, 42);
assert.match(listedZelleUri.url, /\/v1\/pay\/zelle\.uri$/);
assert.match(listedZelleUri.pay_uri, /^mailto:3labsio@gmail.com/);
res = await call(freeEnv, 'GET', '/llms-full.txt');
assert.match(await res.text(), /\/v1\/pay\/zelle\.uri/);
res = await call(freeEnv, 'GET', '/sitemap.xml');
assert.match(await res.text(), /\/v1\/pay\/zelle\.uri/);
res = await call(freeEnv, 'GET', '/v1/invoice');
assert.ok((await res.json()).methods.some((m) => m.scheme === 'zelle' && /^mailto:3labsio@gmail.com/.test(m.uri)));
res = await call(freeEnv, 'GET', '/v1/pay/pack.uri');
assert.strictEqual(res.status, 200);
assert.match(res.headers.get('content-type'), /text\/uri-list/);
assert.match(res.headers.get('link') || '', /rel="payment"/);
assert.equal((await res.text()).trim(), 'https://store.3labs.io/l/agentic-ai-governance-pack?wanted=true');
res = await call(freeEnv, 'GET', '/v1/pay/pack', undefined, { accept: 'text/uri-list' });
assert.match(res.headers.get('content-type'), /text\/uri-list/);
assert.match(await res.text(), /agentic-ai-governance-pack\?wanted=true/);
res = await call(freeEnv, 'GET', '/v1/pay/pack', undefined, { accept: 'application/json' });
const packInvoice = await res.json();
assert.equal(packInvoice.scheme, 'gumroad');
assert.equal(packInvoice.amountUsd, 42);
assert.match(packInvoice.uri, /agentic-ai-governance-pack\?wanted=true/);
res = await call(freeEnv, 'GET', '/openapi.json');
assert.ok((await res.json()).paths['/v1/pay/pack.uri'].get);
assert.match(payManifest.also.pack_uri, /\/v1\/pay\/pack\.uri$/);
const listedPackUri = listed.checkouts.find((o) => o.id === 'pack-uri');
assert.equal(listedPackUri.amount_usd, 42);
assert.match(listedPackUri.url, /\/v1\/pay\/pack\.uri$/);
assert.match(listedPackUri.pay_uri, /agentic-ai-governance-pack\?wanted=true/);
res = await call(freeEnv, 'GET', '/llms-full.txt');
assert.match(await res.text(), /\/v1\/pay\/pack\.uri/);
res = await call(freeEnv, 'GET', '/sitemap.xml');
assert.match(await res.text(), /\/v1\/pay\/pack\.uri/);
res = await call(freeEnv, 'GET', '/v1/invoice');
assert.ok((await res.json()).methods.some((m) => m.scheme === 'gumroad' && /agentic-ai-governance-pack/.test(m.url)));
res = await call(freeEnv, 'GET', '/v1/pay/tip-jar.uri');
assert.strictEqual(res.status, 200);
assert.match(res.headers.get('content-type'), /text\/uri-list/);
assert.match(res.headers.get('link') || '', /rel="payment"/);
assert.equal((await res.text()).trim(), 'https://store.3labs.io/l/tip-jar?wanted=true');
res = await call(freeEnv, 'GET', '/v1/pay/tip-jar', undefined, { accept: 'text/uri-list' });
assert.match(res.headers.get('content-type'), /text\/uri-list/);
assert.match(await res.text(), /tip-jar\?wanted=true/);
res = await call(freeEnv, 'GET', '/v1/pay/tip-jar', undefined, { accept: 'application/json' });
const tipInvoice = await res.json();
assert.equal(tipInvoice.scheme, 'gumroad');
assert.equal(tipInvoice.amountUsd, 42);
assert.match(tipInvoice.uri, /tip-jar\?wanted=true/);
res = await call(freeEnv, 'GET', '/openapi.json');
assert.ok((await res.json()).paths['/v1/pay/tip-jar.uri'].get);
assert.match(payManifest.also.tip_uri, /\/v1\/pay\/tip-jar\.uri$/);
const listedTipUri = listed.checkouts.find((o) => o.id === 'tip-uri');
assert.equal(listedTipUri.amount_usd, 42);
assert.match(listedTipUri.url, /\/v1\/pay\/tip-jar\.uri$/);
assert.match(listedTipUri.pay_uri, /tip-jar\?wanted=true/);
res = await call(freeEnv, 'GET', '/llms-full.txt');
assert.match(await res.text(), /\/v1\/pay\/tip-jar\.uri/);
res = await call(freeEnv, 'GET', '/sitemap.xml');
assert.match(await res.text(), /\/v1\/pay\/tip-jar\.uri/);
res = await call(freeEnv, 'GET', '/v1/invoice');
assert.ok((await res.json()).methods.some((m) => m.scheme === 'gumroad-tip' && /tip-jar/.test(m.url)));
res = await call(freeEnv, 'GET', '/.well-known/security.txt');
assert.strictEqual(res.status, 200);
assert.match(res.headers.get('content-type'), /text\/plain/);
assert.match(res.headers.get('link') || '', /rel="payment"/);
const security = await res.text();
assert.match(security, /Contact: mailto:3labsio@gmail.com/);
assert.match(security, /\/v1\/invoice/);
assert.match(security, /buy\.stripe\.com\/eVq4gA91U3Rr1Yt6z31sQ00/);
assert.match(security, /Expires: 2027-08-16T00:00:00\.000Z/);
assert.match(security, /\/v1\/pay\/card\.uri/);
res = await call(freeEnv, 'GET', '/security.txt');
assert.match(await res.text(), /mailto:3labsio@gmail.com/);
res = await call(freeEnv, 'GET', '/openapi.json');
assert.ok((await res.json()).paths['/.well-known/security.txt'].get);
res = await call(freeEnv, 'GET', '/llms-full.txt');
assert.match(await res.text(), /\/\.well-known\/security\.txt/);
res = await call(freeEnv, 'GET', '/sitemap.xml');
assert.match(await res.text(), /\/\.well-known\/security\.txt/);
assert.match(payManifest.also.security, /\/\.well-known\/security\.txt$/);
res = await call(freeEnv, 'GET', '/humans.txt');
assert.strictEqual(res.status, 200);
assert.match(res.headers.get('content-type'), /text\/plain/);
assert.match(res.headers.get('link') || '', /rel="payment"/);
const humans = await res.text();
assert.match(humans, /\/\* TEAM \*\//);
assert.match(humans, /3labsio@gmail.com/);
assert.match(humans, /buy\.stripe\.com\/eVq4gA91U3Rr1Yt6z31sQ00/);
assert.match(humans, /\/v1\/invoice/);
assert.match(humans, /\/v1\/pay\/card\.uri/);
res = await call(freeEnv, 'GET', '/.well-known/humans.txt');
assert.match(await res.text(), /\/v1\/pay\/usdc\.uri/);
res = await call(freeEnv, 'GET', '/openapi.json');
assert.ok((await res.json()).paths['/humans.txt'].get);
res = await call(freeEnv, 'GET', '/llms-full.txt');
assert.match(await res.text(), /\/humans\.txt/);
res = await call(freeEnv, 'GET', '/sitemap.xml');
assert.match(await res.text(), /\/humans\.txt/);
assert.match(payManifest.also.humans, /\/humans\.txt$/);
res = await call(freeEnv, 'GET', '/.well-known/webfinger?resource=acct:pay@policy-gate.example.workers.dev');
assert.strictEqual(res.status, 200);
assert.match(res.headers.get('content-type'), /application\/jrd\+json/);
assert.match(res.headers.get('link') || '', /rel="payment"/);
const jrd = await res.json();
assert.equal(jrd.subject, 'acct:pay@policy-gate.example.workers.dev');
assert.ok(jrd.links.some((link) => link.rel === 'payment' && link.href === 'https://buy.stripe.com/eVq4gA91U3Rr1Yt6z31sQ00'));
assert.ok(jrd.links.some((link) => /\/v1\/invoice$/.test(link.href)));
assert.ok(jrd.aliases.some((alias) => /fieldproofhq\.github\.io\/offer\//.test(alias)));
res = await call(freeEnv, 'GET', '/.well-known/webfinger?resource=acct:3labsio@gmail.com');
assert.strictEqual(res.status, 200);
assert.equal((await res.json()).subject, 'acct:3labsio@gmail.com');
res = await call(freeEnv, 'GET', '/.well-known/webfinger');
assert.strictEqual(res.status, 400);
res = await call(freeEnv, 'GET', '/.well-known/webfinger?resource=acct:nobody@example.com');
assert.strictEqual(res.status, 404);
res = await call(freeEnv, 'GET', '/.well-known/host-meta');
assert.strictEqual(res.status, 200);
assert.match(res.headers.get('content-type'), /application\/xrd\+xml/);
const hostMeta = await res.text();
assert.match(hostMeta, /webfinger\?resource=\{uri\}/);
assert.match(hostMeta, /buy\.stripe\.com\/eVq4gA91U3Rr1Yt6z31sQ00/);
res = await call(freeEnv, 'GET', '/openapi.json');
assert.ok((await res.json()).paths['/.well-known/webfinger'].get);
res = await call(freeEnv, 'GET', '/llms-full.txt');
assert.match(await res.text(), /webfinger/);
res = await call(freeEnv, 'GET', '/sitemap.xml');
assert.match(await res.text(), /\/\.well-known\/webfinger/);
assert.match(payManifest.also.webfinger, /webfinger\?resource=/);
res = await call(freeEnv, 'GET', '/.well-known/nodeinfo');
assert.strictEqual(res.status, 200);
assert.match(res.headers.get('link') || '', /rel="payment"/);
const nodeIndex = await res.json();
assert.ok(nodeIndex.links.some((link) => link.rel.includes('nodeinfo') && /\/nodeinfo\/2\.1$/.test(link.href)));
res = await call(freeEnv, 'GET', '/nodeinfo/2.1');
assert.strictEqual(res.status, 200);
const node = await res.json();
assert.equal(node.version, '2.1');
assert.ok(node.protocols.includes('x402'));
assert.equal(node.metadata.payment, 'https://buy.stripe.com/eVq4gA91U3Rr1Yt6z31sQ00');
assert.match(node.metadata.invoice, /\/v1\/invoice$/);
assert.match(node.metadata.card_uri, /\/v1\/pay\/card\.uri$/);
res = await call(freeEnv, 'GET', '/.well-known/nodeinfo/2.1');
assert.equal((await res.json()).metadata.payment, node.metadata.payment);
res = await call(freeEnv, 'GET', '/openapi.json');
assert.ok((await res.json()).paths['/.well-known/nodeinfo'].get);
assert.ok((await (await call(freeEnv, 'GET', '/openapi.json')).json()).paths['/nodeinfo/2.1'].get);
res = await call(freeEnv, 'GET', '/llms-full.txt');
assert.match(await res.text(), /\/\.well-known\/nodeinfo/);
res = await call(freeEnv, 'GET', '/sitemap.xml');
assert.match(await res.text(), /\/nodeinfo\/2\.1/);
assert.match(payManifest.also.nodeinfo, /\/\.well-known\/nodeinfo$/);
const quoteEnv = { PAY_TO: '0x07C2383008a9ed30581f27Db5531E19411c94fb3', NETWORK: 'eip155:8453' };
res = await call(quoteEnv, 'GET', '/v1/quote');
assert.strictEqual(res.status, 402);
const quote402 = await res.json();
assert.equal(quote402.accepts[0].maxAmountRequired, '42000000');
assert.equal(quote402.fallback.url, 'https://buy.stripe.com/eVq4gA91U3Rr1Yt6z31sQ00');
assert.match(res.headers.get('link') || '', /rel="payment"/);
res = await call(quoteEnv, 'POST', '/v1/quote');
assert.strictEqual(res.status, 402);
assert.equal((await res.json()).fallback.url, 'https://buy.stripe.com/eVq4gA91U3Rr1Yt6z31sQ00');
res = await call(quoteEnv, 'GET', '/v1/quote', undefined, { accept: 'text/html' });
assert.strictEqual(res.status, 302);
assert.equal(res.headers.get('location'), 'https://buy.stripe.com/eVq4gA91U3Rr1Yt6z31sQ00');
res = await call(freeEnv, 'GET', '/openapi.json');
assert.ok((await res.json()).paths['/v1/quote'].get);
assert.ok((await (await call(freeEnv, 'GET', '/openapi.json')).json()).paths['/v1/quote'].post);
const listedQuote = listed.checkouts.find((o) => o.id === 'quote-42');
assert.equal(listedQuote.amount_usd, 42);
assert.match(listedQuote.url, /\/v1\/quote$/);
res = await call(freeEnv, 'GET', '/llms-full.txt');
assert.match(await res.text(), /\/v1\/quote/);
res = await call(freeEnv, 'GET', '/sitemap.xml');
assert.match(await res.text(), /\/v1\/quote/);
assert.match(payManifest.also.quote, /\/v1\/quote$/);
res = await call(freeEnv, 'GET', '/v1/pay/card.png');
assert.strictEqual(res.status, 302);
const qrLoc = res.headers.get('location') || '';
assert.match(qrLoc, /qrserver\.com\/v1\/create-qr-code/);
assert.match(qrLoc, /buy\.stripe\.com/);
res = await call(freeEnv, 'GET', '/v1/pay/card.qr');
assert.strictEqual(res.status, 302);
assert.match(res.headers.get('location') || '', /buy\.stripe\.com/);
res = await call(freeEnv, 'GET', '/openapi.json');
assert.ok((await res.json()).paths['/v1/pay/card.png'].get);
const listedQr = listed.checkouts.find((o) => o.id === 'card-qr');
assert.equal(listedQr.amount_usd, 42);
assert.match(listedQr.url, /\/v1\/pay\/card\.png$/);
assert.match(listedQr.qr_url, /qrserver\.com/);
res = await call(freeEnv, 'GET', '/llms-full.txt');
assert.match(await res.text(), /\/v1\/pay\/card\.png/);
res = await call(freeEnv, 'GET', '/sitemap.xml');
assert.match(await res.text(), /\/v1\/pay\/card\.png/);
assert.match(payManifest.also.card_qr, /\/v1\/pay\/card\.png$/);
res = await call(freeEnv, 'GET', '/llms-full.txt');
assert.match(await res.text(), /\/v1\/pay\/usdc\.uri/);
assert.match(await (await call(freeEnv, 'GET', '/llms-full.txt')).text(), /\/v1\/pay\/btc\.uri/);
res = await call(freeEnv, 'GET', '/sitemap.xml');
assert.match(await res.text(), /\/v1\/pay\/usdc\.uri/);
assert.match(await (await call(freeEnv, 'GET', '/sitemap.xml')).text(), /\/v1\/pay\/btc\.uri/);

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
res = await call(freeEnv, 'GET', '/v1/received', undefined, { accept: 'text/html' });
assert.strictEqual(res.status, 200);
assert.match(res.headers.get('content-type'), /text\/html/);
const receivedPage = await res.text();
assert.match(receivedPage, /\$42 with card/);
assert.match(receivedPage, /buy\.stripe\.com\/eVq4gA91U3Rr1Yt6z31sQ00/);

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
assert.equal(v1body.fallback.url, 'https://buy.stripe.com/eVq4gA91U3Rr1Yt6z31sQ00');
assert.equal(v1body.fallback.amountUsd, 42);
assert.equal(v1body.fallback.scheme, 'stripe');
assert.equal(v1body.accepts.length, 1, 'card fallback stays out of x402 accepts');
assert.equal(v2.fallback.url, v1body.fallback.url);
assert.match(res.headers.get('link') || '', /rel="payment"/);
assert.match(res.headers.get('link') || '', /buy\.stripe\.com\/eVq4gA91U3Rr1Yt6z31sQ00/);

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
assert.equal(wk.fallback.url, 'https://buy.stripe.com/eVq4gA91U3Rr1Yt6z31sQ00');
assert.equal(wk.resources[0].fallback.url, wk.fallback.url);

res = await call(paidEnv, 'GET', '/v1/check');
assert.strictEqual(res.status, 200, 'GET documents the route; health probes read non-2xx as a dead service');
const getDocs = await res.json();
assert.strictEqual(getDocs.method, 'POST', 'docs name the paid method');
assert.ok(getDocs.accepts?.[0]?.payTo === paidEnv.PAY_TO, 'docs still carry the payment requirements');
assert.equal(getDocs.fallback.url, 'https://buy.stripe.com/eVq4gA91U3Rr1Yt6z31sQ00');
assert.match(res.headers.get('link') || '', /rel="payment"/);

/* 4d — MCP (Streamable HTTP). Discovery channel for agents that speak MCP rather than x402.
   The free tools must be genuinely useful and the paid one must NOT leak a verdict. */
res = await call(paidEnv, 'GET', '/mcp');
assert.strictEqual(res.status, 200);
const mcpDiscover = await res.json();
assert.equal(mcpDiscover.price_usd, 42);
assert.equal(mcpDiscover.currency, 'USDC');
assert.match(mcpDiscover.sponsor, /\/v1\/sponsor$/);
assert.ok(mcpDiscover.tools.includes('first_42_sponsor'));
assert.equal(mcpDiscover.card, 'https://buy.stripe.com/eVq4gA91U3Rr1Yt6z31sQ00');
assert.equal(mcpDiscover.fallback.url, mcpDiscover.card);
assert.match(res.headers.get('link') || '', /rel="payment"/);
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
assert.equal(quoted.fallback.url, 'https://buy.stripe.com/eVq4gA91U3Rr1Yt6z31sQ00');

m = await mcp(paidEnv, 'tools/call', { name: 'first_42_sponsor' });
const sponsorQuote = JSON.parse(m.result.content[0].text);
assert.equal(sponsorQuote.price_usd, 42);
assert.equal(sponsorQuote.amount_atomic, '42000000');
assert.match(sponsorQuote.endpoint, /\/v1\/sponsor$/);
assert.equal(sponsorQuote.accepts[0].maxAmountRequired, '42000000');
assert.notEqual(sponsorQuote.accepts[0].maxAmountRequired, '5000');
assert.equal(sponsorQuote.fallback.url, 'https://buy.stripe.com/eVq4gA91U3Rr1Yt6z31sQ00');
assert.equal(sponsorQuote.fallback.amountUsd, 42);
assert.match(sponsorQuote.invoice, /\/v1\/invoice$/);
assert.match(sponsorQuote.card_uri, /\/v1\/pay\/card\.uri$/);
assert.match(sponsorQuote.usdc_uri, /\/v1\/pay\/usdc\.uri$/);
assert.match(sponsorQuote.btc_uri, /\/v1\/pay\/btc\.uri$/);
assert.equal(sponsorQuote.card, sponsorQuote.fallback.url);
assert.ok(sponsorQuote.methods.some((rail) => rail.scheme === 'stripe' && rail.url === sponsorQuote.card));
assert.ok(sponsorQuote.methods.some((rail) => rail.scheme === 'eip681' && /uint256=42000000/.test(rail.uri)));
assert.ok(sponsorQuote.methods.some((rail) => rail.scheme === 'bip21' && /^bitcoin:bc1q/.test(rail.uri)));
assert.ok(sponsorQuote.methods.some((rail) => rail.scheme === 'zelle' && rail.payTo === '3labsio@gmail.com'));
res = await call(paidEnv, 'GET', '/mcp');
const mcpHome = await res.json();
assert.match(mcpHome.invoice, /\/v1\/invoice$/);
assert.match(mcpHome.card_uri, /\/v1\/pay\/card\.uri$/);
res = await call(paidEnv, 'GET', '/.well-known/mcp.json');
const mcpManifest = await res.json();
assert.match(mcpManifest.invoice, /\/v1\/invoice$/);
assert.match(mcpManifest.card_uri, /\/v1\/pay\/card\.uri$/);

/* free mode is the one place it may answer */
m = await mcp(freeEnv, 'tools/call', { name: 'policy_check', arguments: { request: { action: 'gmail.read' } } });
assert.strictEqual(JSON.parse(m.result.content[0].text).decision, 'allow', 'free mode answers');

m = await mcp(paidEnv, 'tools/call', { name: 'no_such_tool' });
assert.strictEqual(m.error.code, -32602, 'unknown tool -> JSON-RPC error, not a crash');
m = await mcp(paidEnv, 'bogus/method');
assert.strictEqual(m.error.code, -32601, 'unknown method -> method not found');

/* 4e — Ethics Check. Built 2026-08-11, shipped 2026-08-16. The Policy Gate answers
   "am I allowed"; this answers "should I". Free canons, paid screening. */
res = await call(paidEnv, 'GET', '/v1/canons');
assert.strictEqual(res.status, 200, 'canons are free — you can read what you would be buying');
const canons = await res.json();
assert.strictEqual(canons.canons.length, 7, 'seven canons');
assert.ok(canons.framing.includes('cannot see what you do not declare'),
  'the honest limitation must ship with the product, not just the marketing');

res = await call(paidEnv, 'GET', '/v1/ethics-check');
assert.strictEqual(res.status, 200, 'GET documents the paid route; non-2xx reads as dead to probes');

res = await call(paidEnv, 'POST', '/v1/ethics-check', { action: 'x.read' });
assert.strictEqual(res.status, 402, 'the screening itself is paid');
const ethQuote = await res.json();
assert.strictEqual(ethQuote.accepts[0].maxAmountRequired, '10000', '$0.01 = 10000 atomic USDC');

/* free mode answers, and the engine actually discriminates */
res = await call(freeEnv, 'POST', '/v1/ethics-check', {
  action: 'storage.delete',
  summary: 'wipe production',
  declared: { reversible: false, affects_others: true, consent: 'absent', deception: false,
    disclosure: true, impact_usd: 5000, data_sensitivity: 'personal',
    targets_individual: false, urgency_claimed: true },
});
const harsh = await res.json();
assert.strictEqual(harsh.verdict, 'stop', 'an irreversible unconsented $5000 wipe must not come back clear');
assert.ok(harsh.flags.length >= 3 && harsh.questions.length >= 1, 'flags and reflective questions returned');

res = await call(freeEnv, 'POST', '/v1/ethics-check', {
  action: 'docs.read',
  summary: 'read public documentation',
  declared: { reversible: true, affects_others: false, consent: 'not_required', deception: false,
    disclosure: true, impact_usd: 0, data_sensitivity: 'public',
    targets_individual: false, urgency_claimed: false },
});
assert.strictEqual((await res.json()).verdict, 'clear', 'a harmless read must come back clear, or the engine is just a stamp');

/* 5 — CORS preflight */
res = await worker.fetch(new Request(base + '/v1/check', { method: 'OPTIONS' }), freeEnv);
assert.strictEqual(res.status, 204);
assert.ok(res.headers.get('access-control-allow-origin'));

console.log(`OK — ${pass} verdict cases + 5 engine checks + 13 HTTP checks passed`);
