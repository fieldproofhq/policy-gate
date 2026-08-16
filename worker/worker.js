/**
 * Fieldproof Policy Gate — Cloudflare Worker v0.2
 * Zero dependencies. Deploys on the Workers free tier.
 *
 * The API that answers: "Am I allowed to do this?" — sold to agents, paid by
 * agents, per call, over x402 (v2 with v1 compatibility).
 *
 * Endpoints:
 *   GET  /            service info (agent-friendly discovery JSON)
 *   GET  /healthz     liveness
 *   GET  /v1/policies list built-in policy ids
 *   GET  /v1/received public Base USDC observation of PAY_TO (self-test excluded)
 *   POST /v1/check    evaluate { request, policy | policy_id } -> verdict
 *
 * Modes (env vars, all optional — defaults to FREE):
 *   PAY_TO        USDC receiving address on Base. Unset => FREE_MODE.
 *   FREE_MODE     "true"/"false" override. Unset => free unless PAY_TO set.
 *   NETWORK       CAIP-2 id, default "eip155:8453" (Base mainnet).
 *                 Use "eip155:84532" (Base Sepolia) for dry runs.
 *   PRICE_USD     default "0.005" (=> 5000 atomic USDC units, 6 decimals)
 *   FACILITATOR_URL  default: CDP mainnet facilitator when CDP keys present,
 *                    else https://x402.org/facilitator (testnet only).
 *   CDP_KEY_ID / CDP_KEY_SECRET  Coinbase CDP API key (Ed25519) — required for
 *                    the CDP facilitator (mainnet settlement). Secrets, not vars.
 */

'use strict';

/* ----------------------------- policy engine ------------------------------ */

const DECISIONS = new Set(['allow', 'require_approval', 'deny']);

function globMatch(pattern, value) {
  const re = new RegExp(
    '^' +
      pattern
        .split(/(\*\*|\*)/)
        .map((part) => {
          if (part === '**') return '.*';
          if (part === '*') return '[^.]*';
          return part.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        })
        .join('') +
      '$'
  );
  return re.test(value);
}

function condMatches(cond, params) {
  const val = params?.[cond.param];
  if (val === undefined || val === null) return cond.if_missing === 'match';
  if ('gt' in cond) return typeof val === 'number' && val > cond.gt;
  if ('gte' in cond) return typeof val === 'number' && val >= cond.gte;
  if ('lt' in cond) return typeof val === 'number' && val < cond.lt;
  if ('lte' in cond) return typeof val === 'number' && val <= cond.lte;
  if ('eq' in cond) return val === cond.eq;
  if ('in' in cond) return Array.isArray(cond.in) && cond.in.includes(val);
  if ('matches' in cond) return typeof val === 'string' && new RegExp(cond.matches).test(val);
  return false;
}

function ruleMatches(rule, req) {
  const m = rule.match || {};
  if (m.action && !globMatch(m.action, req.action)) return false;
  if (m.actor && !globMatch(m.actor, req.actor || '')) return false;
  if (Array.isArray(m.where)) {
    for (const cond of m.where) {
      if (!condMatches(cond, req.params)) return false;
    }
  }
  return true;
}

function validatePolicy(policy) {
  const errors = [];
  if (!policy || typeof policy !== 'object') return ['policy must be an object'];
  if (policy.default && !DECISIONS.has(policy.default)) {
    errors.push(`default must be one of ${[...DECISIONS].join('|')}`);
  }
  const tiers = policy.tiers || {};
  for (const [k, t] of Object.entries(tiers)) {
    if (!DECISIONS.has(t.decision)) errors.push(`tier ${k}: bad decision "${t.decision}"`);
  }
  (policy.rules || []).forEach((r, i) => {
    if (r.tier === undefined && !DECISIONS.has(r.decision)) {
      errors.push(`rule ${r.id || i}: needs "tier" or a valid "decision"`);
    }
    if (r.tier !== undefined && !tiers[String(r.tier)]) {
      errors.push(`rule ${r.id || i}: tier ${r.tier} not defined in policy.tiers`);
    }
  });
  return errors;
}

function check(policy, request) {
  const errors = validatePolicy(policy);
  if (errors.length) return { error: 'invalid_policy', details: errors };
  if (!request || typeof request.action !== 'string' || !request.action.length) {
    return { error: 'invalid_request', details: ['request.action (string) is required'] };
  }
  const rules = policy.rules || [];
  for (const rule of rules) {
    if (!ruleMatches(rule, request)) continue;
    const tier = rule.tier !== undefined ? String(rule.tier) : null;
    const decision = tier !== null ? policy.tiers[tier].decision : rule.decision;
    return {
      decision,
      matched_rule: rule.id || null,
      tier: tier !== null ? Number(tier) : null,
      tier_label: tier !== null ? policy.tiers[tier].label || null : null,
      rationale:
        rule.rationale ||
        `Matched rule "${rule.id || 'unnamed'}"` +
          (tier !== null ? ` (tier ${tier}: ${policy.tiers[tier].label || 'unlabeled'})` : ''),
      policy_version: policy.version || null,
      default_applied: false,
    };
  }
  const def = policy.default || 'deny';
  return {
    decision: def,
    matched_rule: null,
    tier: null,
    tier_label: null,
    rationale: `No rule matched; policy default is "${def}".`,
    policy_version: policy.version || null,
    default_applied: true,
  };
}

/* --------------------------- built-in policies ---------------------------- */

const DEFAULT_POLICY = {
  version: '0.1',
  name: 'fieldproof-default-action-tiers',
  description:
    'Reference policy from the Fieldproof Agentic AI Governance Pack: four action tiers, default-deny, money and deletion gated to humans.',
  default: 'deny',
  tiers: {
    0: { decision: 'allow', label: 'read-only' },
    1: { decision: 'allow', label: 'reversible write' },
    2: { decision: 'require_approval', label: 'hard to reverse — human approval' },
    3: { decision: 'deny', label: 'forbidden for agents' },
  },
  rules: [
    { id: 'read-anything', match: { action: '*.read' }, tier: 0, rationale: 'Reads are tier 0: no side effects.' },
    { id: 'list-search', match: { action: '*.list' }, tier: 0 },
    {
      id: 'small-payments-need-approval',
      match: { action: 'payments.send', where: [{ param: 'amount_usd', lte: 50 }] },
      tier: 2,
      rationale: 'Any outbound payment is at least tier 2; small ones may be approved quickly.',
    },
    {
      id: 'large-payments-forbidden',
      match: { action: 'payments.send', where: [{ param: 'amount_usd', gt: 50 }] },
      tier: 3,
      rationale: 'Payments over $50 are outside agent authority entirely.',
    },
    {
      id: 'payments-unknown-amount',
      match: { action: 'payments.send' },
      tier: 3,
      rationale: 'Payment with unspecified amount: treat as worst case.',
    },
    { id: 'no-deletes', match: { action: '**.delete' }, tier: 3, rationale: 'Agents never delete data.' },
    { id: 'no-credentials', match: { action: 'auth.**' }, tier: 3, rationale: 'Credential and account operations are human-only.' },
    { id: 'content-updates-ok', match: { action: 'content.update' }, tier: 1, rationale: 'Content edits are versioned and reversible.' },
    {
      id: 'outbound-messages-first-contact',
      match: { action: 'messages.send', where: [{ param: 'prior_contact', eq: false }] },
      tier: 2,
      rationale: 'First contact with a new party is new-in-kind: stage for human approval.',
    },
    {
      id: 'outbound-messages-known-thread',
      match: { action: 'messages.send', where: [{ param: 'prior_contact', eq: true }] },
      tier: 1,
    },
  ],
};

const BUILTINS = { 'default-action-tiers': DEFAULT_POLICY };

/* --------------------------------- MCP tools ------------------------------- */

const MCP_TOOLS = [
  {
    name: 'policy_example',
    description:
      'Free. Worked allow/require_approval/deny verdicts from the live policy engine, so you can judge the service before paying for it.',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'policy_rules',
    description:
      'Free. The full built-in policy: every tier, rule, condition and rationale. Nothing about how a verdict is reached is hidden.',
    inputSchema: { type: 'object', properties: {} },
  },
  {
    name: 'policy_check',
    description:
      'Evaluate a proposed agent action against a policy and return allow / require_approval / deny with the matched rule and rationale. Paid per call via x402 ($0.005 USDC on Base); returns signing instructions when unpaid.',
    inputSchema: {
      type: 'object',
      required: ['request'],
      properties: {
        request: {
          type: 'object',
          required: ['action'],
          properties: {
            action: { type: 'string', description: 'Dotted action id, e.g. payments.send' },
            actor: { type: 'string' },
            params: { type: 'object' },
          },
        },
        policy_id: { type: 'string', description: 'Built-in policy id; see policy_rules' },
        policy: { type: 'object', description: 'Your own policy document, evaluated instead of ours' },
      },
    },
  },
];

/* ------------------------------ x402 helpers ------------------------------ */

const USDC = {
  'eip155:8453': { asset: '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913', extra: { name: 'USD Coin', version: '2' } },
  'eip155:84532': { asset: '0x036CbD53842c5426634e7929541eC2318f3dCF7e', extra: { name: 'USDC', version: '2' } },
};

const CDP_FACILITATOR = 'https://api.cdp.coinbase.com/platform/v2/x402';
const TESTNET_FACILITATOR = 'https://x402.org/facilitator';

function b64encode(obj) {
  return btoa(String.fromCharCode(...new TextEncoder().encode(JSON.stringify(obj))));
}
function b64decode(str) {
  try {
    const bytes = Uint8Array.from(atob(str), (c) => c.charCodeAt(0));
    return JSON.parse(new TextDecoder().decode(bytes));
  } catch {
    return null;
  }
}
function b64url(bytes) {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function cfg(env) {
  const payTo = env.PAY_TO || null;
  const free = env.FREE_MODE !== undefined ? env.FREE_MODE !== 'false' : !payTo;
  const network = env.NETWORK || 'eip155:8453';
  const priceUsd = env.PRICE_USD || '0.005';
  const amount = String(Math.round(parseFloat(priceUsd) * 1e6)); // USDC 6 decimals
  const hasCdp = !!(env.CDP_KEY_ID && env.CDP_KEY_SECRET);
  const facilitator = env.FACILITATOR_URL || (hasCdp ? CDP_FACILITATOR : TESTNET_FACILITATOR);
  return { payTo, free, network, priceUsd, amount, facilitator, hasCdp };
}

/** v1 network names vs v2 CAIP-2 ids — the facilitator rejects mixed schemas. */
const V1_NETWORK = { 'eip155:8453': 'base', 'eip155:84532': 'base-sepolia' };

/** x402 v1 requirements: network NAME, maxAmountRequired, resource/description/mimeType required. */
function paymentRequirementsV1(c, url) {
  const token = USDC[c.network] || USDC['eip155:8453'];
  return {
    scheme: 'exact',
    network: V1_NETWORK[c.network] || 'base',
    maxAmountRequired: c.amount,
    resource: url,
    // The 402 is the only thing most callers will ever read. It should answer "why would
    // I pay this?" without a second request.
    description:
      'Deterministic allow / require_approval / deny verdict for a proposed agent action. ' +
      'Same input always yields the same verdict, with the matched rule and rationale returned so it is auditable. ' +
      'Evaluate before paying — GET /v1/example and GET /v1/policies are free and hide nothing.',
    mimeType: 'application/json',
    payTo: c.payTo,
    maxTimeoutSeconds: 60,
    asset: token.asset,
    extra: token.extra,
  };
}

/** x402 v2 requirements: CAIP-2 network, amount; NO resource/description/mimeType here. */
function paymentRequirementsV2(c) {
  const token = USDC[c.network] || USDC['eip155:8453'];
  return {
    scheme: 'exact',
    network: c.network,
    amount: c.amount,
    asset: token.asset,
    payTo: c.payTo,
    maxTimeoutSeconds: 60,
    extra: token.extra,
  };
}

const SELF_TEST_USD = 0.005;
const GOAL_USD = 42;
const BASE_USDC = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
const BASE_RPCS = ['https://mainnet.base.org', 'https://base.publicnode.com', 'https://1rpc.io/base'];

async function readUsdcBalance(address, fetchImpl = fetch) {
  const data = '0x70a08231' + address.toLowerCase().replace('0x', '').padStart(64, '0');
  const payload = JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'eth_call', params: [{ to: BASE_USDC, data }, 'latest'] });
  let last = 'rpc_failed';
  for (const rpc of BASE_RPCS) {
    try {
      const response = await fetchImpl(rpc, { method: 'POST', headers: { 'content-type': 'application/json' }, body: payload });
      const body = await response.json();
      if (body.result) return Number(BigInt(body.result)) / 1e6;
      last = JSON.stringify(body.error || body).slice(0, 160);
    } catch (err) {
      last = String(err && err.message ? err.message : err).slice(0, 160);
    }
  }
  throw new Error(last);
}

function assessReceived(balanceUsd, observedAt = new Date().toISOString()) {
  if (!Number.isFinite(balanceUsd) || balanceUsd < 0) throw new Error('balance must be a non-negative finite number');
  const externalUsd = Math.max(0, Number((balanceUsd - SELF_TEST_USD).toFixed(6)));
  return {
    observedAt,
    walletUsd: balanceUsd,
    selfTestUsd: SELF_TEST_USD,
    externalUsd,
    goalUsd: GOAL_USD,
    goalMet: externalUsd >= GOAL_USD,
    remainingUsd: Math.max(0, Number((GOAL_USD - externalUsd).toFixed(6))),
  };
}

function checkouts(c, origin) {
  return [
    {
      id: 'governance-pack',
      url: 'https://store.3labs.io/l/agentic-ai-governance-pack',
      asset: 'USD',
      amount_usd: 59,
      meets_first_42: true,
      note: 'human checkout; one sale meets the $42 external-income bar',
    },
    {
      id: 'tip-jar',
      url: 'https://fieldproof.gumroad.com/l/tip-jar',
      asset: 'USD',
      amount_usd: null,
      meets_first_42: false,
      note: 'pay-what-you-want; counts only if a stranger pays',
    },
    {
      id: 'x402-check',
      url: `${origin}/v1/check`,
      asset: 'USDC',
      amount_usd: Number(c.priceUsd),
      pay_to: c.payTo,
      network: c.network,
      meets_first_42: false,
      note: 'agent x402; unpaid POST quotes the public receive wallet',
    },
    {
      id: 'usdc-direct',
      url: c.payTo ? `https://basescan.org/address/${c.payTo}` : null,
      asset: 'USDC',
      amount_usd: 42,
      pay_to: c.payTo,
      network: c.network,
      meets_first_42: true,
      note: 'already-approved public receive wallet; one 42 USDC transfer on Base meets the bar',
    },
    {
      id: 'zelle',
      url: 'https://fieldproofhq.github.io/#support',
      asset: 'USD',
      amount_usd: 42,
      pay_to: '3labsio@gmail.com',
      meets_first_42: true,
      note: 'already-approved public Zelle; memo Fieldproof',
    },
  ];
}

function bazaarExtension(origin) {
  return {
    bazaar: {
      info: {
        input: {
          type: 'http',
          method: 'POST',
          bodyType: 'json',
          bodyFields: {
            request: { action: 'payments.send', actor: 'my-agent', params: { amount_usd: 25 } },
            policy_id: 'default-action-tiers',
          },
        },
        output: {
          type: 'json',
          example: {
            decision: 'require_approval',
            matched_rule: 'small-payments-need-approval',
            tier: 2,
            tier_label: 'hard to reverse — human approval',
            rationale: 'Any outbound payment is at least tier 2; small ones may be approved quickly.',
            policy_version: '0.1',
          },
        },
      },
      schema: {
        type: 'object',
        properties: {
          request: {
            type: 'object',
            required: ['action'],
            properties: {
              action: { type: 'string', description: 'Dotted action id, e.g. payments.send' },
              actor: { type: 'string' },
              params: { type: 'object' },
            },
          },
          policy: { type: 'object', description: 'Inline policy document (alternative to policy_id)' },
          policy_id: { type: 'string', description: 'Built-in policy id; see GET /v1/policies' },
        },
      },
    },
  };
}

function paymentRequired402(c, url, origin, errMsg) {
  const v2 = {
    x402Version: 2,
    error: errMsg || 'PAYMENT-SIGNATURE header is required',
    resource: {
      url,
      description: 'Fieldproof Policy Gate — deterministic allow/require_approval/deny verdicts for agent actions',
      mimeType: 'application/json',
      serviceName: 'Fieldproof Policy Gate',
      tags: ['governance', 'policy', 'safety', 'agents'],
    },
    accepts: [paymentRequirementsV2(c)],
    extensions: bazaarExtension(origin),
  };
  // v1-compatible body for older clients (v1 dialect: network name + maxAmountRequired):
  const v1Body = { x402Version: 1, error: v2.error, accepts: [paymentRequirementsV1(c, url)] };
  return new Response(JSON.stringify(v1Body, null, 2), {
    status: 402,
    headers: {
      'content-type': 'application/json',
      'PAYMENT-REQUIRED': b64encode(v2),
      ...corsHeaders(),
    },
  });
}

/** Ed25519 JWT for Coinbase CDP (zero-dep, WebCrypto). */
async function cdpJwt(env, method, urlStr) {
  const u = new URL(urlStr);
  const keyId = env.CDP_KEY_ID;
  const secret = Uint8Array.from(atob(env.CDP_KEY_SECRET), (c) => c.charCodeAt(0));
  const seed = secret.slice(0, 32); // CDP Ed25519 secret = 64 bytes (seed || pub)
  // Wrap raw seed in PKCS8 DER for WebCrypto import:
  const pkcs8Prefix = Uint8Array.from([
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
  ]);
  const pkcs8 = new Uint8Array(pkcs8Prefix.length + seed.length);
  pkcs8.set(pkcs8Prefix), pkcs8.set(seed, pkcs8Prefix.length);
  const key = await crypto.subtle.importKey('pkcs8', pkcs8, { name: 'Ed25519' }, false, ['sign']);
  const now = Math.floor(Date.now() / 1000);
  const nonce = b64url(crypto.getRandomValues(new Uint8Array(16)));
  const header = { alg: 'EdDSA', typ: 'JWT', kid: keyId, nonce };
  const claims = {
    iss: 'cdp',
    sub: keyId,
    aud: ['cdp_service'],
    nbf: now,
    exp: now + 120,
    uri: `${method} ${u.host}${u.pathname}`,
  };
  const enc = (o) => b64url(new TextEncoder().encode(JSON.stringify(o)));
  const signingInput = `${enc(header)}.${enc(claims)}`;
  const sig = await crypto.subtle.sign('Ed25519', key, new TextEncoder().encode(signingInput));
  return `${signingInput}.${b64url(new Uint8Array(sig))}`;
}

async function facilitatorCall(env, c, endpoint, body) {
  const url = `${c.facilitator}/${endpoint}`;
  const headers = { 'content-type': 'application/json' };
  if (c.facilitator.startsWith(CDP_FACILITATOR.slice(0, 30)) && c.hasCdp) {
    headers.authorization = `Bearer ${await cdpJwt(env, 'POST', url)}`;
  }
  const res = await fetch(url, { method: 'POST', headers, body: JSON.stringify(body) });
  let json = null;
  try {
    json = await res.json();
  } catch {
    /* non-JSON facilitator error */
  }
  return { status: res.status, json };
}

/* ------------------------------- HTTP layer -------------------------------- */

function corsHeaders() {
  return {
    'access-control-allow-origin': '*',
    'access-control-allow-methods': 'GET, POST, OPTIONS',
    'access-control-allow-headers': 'content-type, x-payment, payment-signature',
    'access-control-expose-headers': 'payment-required, payment-response, x-payment-response, x-fieldproof-free',
  };
}

function json(code, obj, extraHeaders = {}, free = false) {
  const headers = { 'content-type': 'application/json', ...corsHeaders(), ...extraHeaders };
  if (free) headers['x-fieldproof-free'] = 'true; x402 pricing live soon - follow @FieldProofAI';
  return new Response(JSON.stringify(obj, null, 2), { status: code, headers });
}

const MAX_BODY = 64 * 1024;

async function handleCheck(request, env, c, url) {
  const raw = await request.text();
  if (raw.length > MAX_BODY) return json(413, { error: 'body_too_large', max_bytes: MAX_BODY });
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return json(400, { error: 'invalid_json' }, {}, c.free);
  }
  const policy = parsed.policy || BUILTINS[parsed.policy_id];
  if (!policy)
    return json(
      400,
      { error: 'no_policy', hint: 'send "policy" inline or a known "policy_id"; GET /v1/policies lists built-ins' },
      {},
      c.free
    );
  const verdict = check(policy, parsed.request);
  if (verdict.error) return json(422, verdict, {}, c.free);
  return { verdict }; // caller wraps (payment headers may be added)
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const c = cfg(env);

    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: corsHeaders() });

    if (request.method === 'GET' && url.pathname === '/healthz') return json(200, { ok: true }, {}, c.free);

    // MCP (Streamable HTTP). x402 directories reach agents that already speak x402; MCP is
    // how most agents actually acquire tools, and it is a far larger population. The free
    // surfaces are exposed as real tools so an agent can evaluate the service inside its own
    // client; the paid verdict returns signing instructions rather than the answer, so this
    // is a discovery channel and not a giveaway of the product.
    if (url.pathname === '/mcp') {
      if (request.method === 'GET') {
        return json(200, { transport: 'streamable-http', protocol: 'mcp', usage: 'POST JSON-RPC 2.0 here', tools: MCP_TOOLS.map((t) => t.name) }, {}, true);
      }
      if (request.method !== 'POST') return json(405, { error: 'method_not_allowed' }, {}, true);

      let rpc;
      try { rpc = JSON.parse(await request.text()); } catch { return json(200, { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } }, {}, true); }
      const reply = (result) => json(200, { jsonrpc: '2.0', id: rpc.id ?? null, result }, {}, true);
      const fail = (code, message) => json(200, { jsonrpc: '2.0', id: rpc.id ?? null, error: { code, message } }, {}, true);

      switch (rpc.method) {
        case 'initialize':
          return reply({
            protocolVersion: typeof rpc.params?.protocolVersion === 'string' ? rpc.params.protocolVersion : '2025-06-18',
            capabilities: { tools: {} },
            serverInfo: { name: 'fieldproof-policy-gate', version: '0.2' },
            instructions:
              'Deterministic allow / require_approval / deny verdicts for proposed agent actions. policy_example and policy_rules are free; policy_check returns x402 payment instructions.',
          });
        case 'notifications/initialized':
          return new Response(null, { status: 202, headers: corsHeaders() });
        case 'ping':
          return reply({});
        case 'tools/list':
          return reply({ tools: MCP_TOOLS });
        case 'tools/call': {
          const name = rpc.params?.name;
          const args = rpc.params?.arguments || {};
          const text = (obj) => reply({ content: [{ type: 'text', text: JSON.stringify(obj, null, 2) }] });

          if (name === 'policy_rules') return text({ policies: Object.keys(BUILTINS), definitions: BUILTINS });
          if (name === 'policy_example') {
            const samples = [
              { action: 'docs.read' },
              { action: 'payments.send', params: { amount_usd: 20 } },
              { action: 'storage.delete' },
            ];
            return text({ examples: samples.map((r) => ({ request: r, verdict: check(DEFAULT_POLICY, r) })) });
          }
          if (name === 'policy_check') {
            const policy = args.policy || BUILTINS[args.policy_id || 'default-action-tiers'];
            const req = args.request;
            if (!req?.action) return text({ error: 'request.action is required' });
            if (c.free) return text(check(policy, req));
            // Paid: quote the price rather than answer. The verdict itself stays behind x402.
            return text({
              payment_required: true,
              price_usd: c.priceUsd,
              endpoint: `${url.origin}/v1/check`,
              accepts: [paymentRequirementsV1(c, `${url.origin}/v1/check`)],
              how: 'POST the endpoint with an X-PAYMENT header (x402). Free evaluation: policy_example, policy_rules.',
            });
          }
          return fail(-32602, `Unknown tool: ${name}`);
        }
        default:
          return fail(-32601, `Method not found: ${rpc.method}`);
      }
    }

    if (request.method === 'GET' && (url.pathname === '/' || url.pathname === '')) {
      return json(
        200,
        {
          service: 'Fieldproof Policy Gate',
          version: '0.2',
          description:
            'Deterministic policy verdicts for autonomous agents: allow | require_approval | deny. The policy this AI-run business operates under, as an API.',
          endpoints: {
            check: 'POST /v1/check',
            policies: 'GET /v1/policies',
            example: 'GET /v1/example  (free — worked verdicts from the live engine)',
            received: 'GET /v1/received  (free — public USDC observation of PAY_TO; self-test excluded)',
            health: 'GET /healthz',
          },
          evaluate_before_paying: 'GET /v1/example and GET /v1/policies are free and complete. Nothing about the verdict logic is hidden behind the paywall.',
          pricing: c.free
            ? { mode: 'free', note: 'x402 pricing ($0.005/check, USDC on Base) coming soon' }
            : { mode: 'x402', price_usd: c.priceUsd, network: c.network, protocol: 'x402 v2 (v1 compatible)' },
          docs: 'https://github.com/fieldproofhq/policy-gate',
          operator: 'https://fieldproofhq.github.io',
          store: 'https://store.3labs.io',
          x: 'https://x.com/FieldProofAI',
          checkouts: checkouts(c, url.origin),
        },
        {},
        c.free
      );
    }

    if (request.method === 'GET' && url.pathname === '/v1/checkouts') {
      return json(200, { checkouts: checkouts(c, url.origin) }, {}, c.free);
    }

    if (request.method === 'GET' && url.pathname === '/v1/received') {
      if (!c.payTo) {
        return json(200, { status: 'unavailable', externalUsd: null, goalUsd: GOAL_USD, goalMet: false, note: 'PAY_TO is unset', checkouts: checkouts(c, url.origin) }, {}, true);
      }
      try {
        const balanceUsd = await readUsdcBalance(c.payTo);
        const observed = assessReceived(balanceUsd);
        return json(
          200,
          {
            status: 'observed',
            wallet: c.payTo,
            network: c.network,
            ...observed,
            note: 'Public Base USDC read of the receive wallet. The $0.005 self-test is excluded. A 402 or storefront HTTP 200 is not income.',
            checkouts: checkouts(c, url.origin),
          },
          {},
          true
        );
      } catch (err) {
        return json(502, { status: 'unavailable', error: 'rpc_failed', detail: String(err && err.message ? err.message : err).slice(0, 160), goalUsd: GOAL_USD, goalMet: false }, {}, true);
      }
    }

    // Domain-ownership proof for the official MCP registry. Ed25519 PUBLIC key only —
    // the private half exists solely outside this repo and is never committed. Publishing
    // to the official registry matters because downstream directories consume its API, so
    // one verified entry propagates rather than needing a submission per directory.
    if (request.method === 'GET' && url.pathname === '/.well-known/mcp-registry-auth') {
      return new Response('v=MCPv1; k=ed25519; p=EGbytDYPTQb3C/N/jNxx/kq5l8U5kXJTeW5Kw4yXsAM=', {
        status: 200,
        headers: { 'content-type': 'text/plain; charset=utf-8', ...corsHeaders() },
      });
    }

    // Domain-ownership proof for the 402index.io directory. This is the SHA-256 hash of a
    // verification token, not the token itself — the hash is designed to be public and the
    // token never touches a file in this repo. Serving it proves we control the origin and
    // upgrades our listing from "pending review" to approved.
    if (request.method === 'GET' && url.pathname === '/.well-known/402index-verify.txt') {
      return new Response('725eddf8d73ca58a9890434155f994b9a43ecef4016ea6cdb9a4f3b8c1ee8d58', {
        status: 200,
        headers: { 'content-type': 'text/plain; charset=utf-8', ...corsHeaders() },
      });
    }

    // Discovery manifest. Crawlers and directories look here first; without it a service
    // is invisible to anything that does not already know the exact POST route. Rejected
    // by agent-tools.cloud on 2026-08-16 for precisely this: "no /.well-known/x402 and no
    // 402 challenge from endpoint" — their prober GETs, and GET used to 404.
    if (request.method === 'GET' && url.pathname === '/.well-known/x402') {
      return json(
        200,
        {
          x402Version: 2,
          serviceName: 'Fieldproof Policy Gate',
          description:
            'Deterministic allow / require_approval / deny verdicts for proposed agent actions. Same input, same verdict, with the matched rule and rationale returned so it is auditable.',
          tags: ['governance', 'policy', 'safety', 'agents'],
          resources: [
            {
              url: `${url.origin}/v1/check`,
              method: 'POST',
              mimeType: 'application/json',
              description: 'Evaluate a proposed action against a policy and return a verdict',
              accepts: c.free ? [] : [paymentRequirementsV2(c)],
              free: c.free,
              evaluate_before_paying: [`${url.origin}/v1/example`, `${url.origin}/v1/policies`],
            },
          ],
          docs: 'https://github.com/fieldproofhq/policy-gate',
          contact: 'https://github.com/fieldproofhq/policy-gate/issues',
        },
        {},
        true
      );
    }

    // A GET on the paid route documents it; it does not 404 and it does not 402.
    //
    // GET is not the paid operation — POST is — and directory health probes read a non-2xx
    // GET as a dead service. Ours was marked `health: down` for exactly that, while every
    // healthy listing answered 200. This returns docs-only JSON carrying the full `accepts`
    // block, which is the pattern those directories document ("if the probe returned
    // docs-only JSON, follow its request schema"), so machines still learn the price here.
    if (request.method === 'GET' && url.pathname === '/v1/check') {
      return json(
        200,
        {
          endpoint: `${url.origin}/v1/check`,
          method: 'POST',
          paid: !c.free,
          usage: 'POST { "policy_id": "default-action-tiers" | "policy": {...}, "request": { "action": "...", "params": {...} } }',
          accepts: c.free ? [] : [paymentRequirementsV1(c, url.href)],
          price_usd: c.free ? 0 : c.priceUsd,
          protocol: c.free ? 'free mode' : 'x402 — POST without payment returns 402 with signing instructions',
          evaluate_before_paying: [`${url.origin}/v1/example`, `${url.origin}/v1/policies`],
          discovery: `${url.origin}/.well-known/x402`,
        },
        {},
        true
      );
    }

    if (request.method === 'GET' && url.pathname === '/v1/policies') {
      // The ruleset is documentation, not the product. What is sold is the evaluation —
      // deterministic, versioned, and auditable. Returning only opaque ids meant nobody
      // deciding whether to pay could see what a verdict is grounded in.
      return json(
        200,
        {
          policies: Object.keys(BUILTINS),
          definitions: BUILTINS,
          note: 'Policies are public on purpose: you are paying for the verdict, not the rules. GET /v1/example for worked verdicts.',
        },
        {},
        c.free
      );
    }

    // Free worked examples, computed by the same evaluator that serves paid traffic.
    // Nothing here is canned: if the engine changes, these change with it, which is the
    // only version of this endpoint worth trusting.
    if (request.method === 'GET' && url.pathname === '/v1/example') {
      const samples = [
        { label: 'read-only action', request: { action: 'docs.read', params: { path: '/README' } } },
        { label: 'small payment', request: { action: 'payments.send', params: { amount_usd: 20 } } },
        { label: 'large payment', request: { action: 'payments.send', params: { amount_usd: 500 } } },
        { label: 'deletion', request: { action: 'storage.delete', params: { key: 'prod/db' } } },
        { label: 'first contact message', request: { action: 'messages.send', params: { prior_contact: false } } },
        { label: 'unmatched action (default applies)', request: { action: 'something.novel' } },
      ];
      return json(
        200,
        {
          policy_id: 'default-action-tiers',
          note: 'These verdicts are produced live by the same function that answers POST /v1/check. Paying buys the same evaluation over YOUR policy and YOUR action.',
          examples: samples.map((s) => ({
            label: s.label,
            request: s.request,
            verdict: check(DEFAULT_POLICY, s.request),
          })),
          // The question a buyer actually has is not "what is your policy?" but "can I
          // express MINE?". Showing our ruleset alone never answers it, so this proves
          // bring-your-own works — again on the live engine, not in prose.
          bring_your_own_policy: (() => {
            const yours = {
              version: '1.0',
              name: 'your-policy',
              default: 'require_approval',
              tiers: { 0: { decision: 'allow', label: 'safe' }, 3: { decision: 'deny', label: 'never' } },
              rules: [
                { id: 'your-reads-are-fine', match: { action: 'db.read' }, tier: 0, rationale: 'Your rule, your wording.' },
                { id: 'never-touch-prod', match: { action: 'prod.**' }, tier: 3, rationale: 'Your call, enforced identically.' },
              ],
            };
            return {
              note: 'Send any policy document inline as "policy" — you are not limited to ours, and nothing about your policy is stored.',
              policy: yours,
              results: [
                { request: { action: 'db.read' }, verdict: check(yours, { action: 'db.read' }) },
                { request: { action: 'prod.deploy' }, verdict: check(yours, { action: 'prod.deploy' }) },
                { request: { action: 'anything.else' }, verdict: check(yours, { action: 'anything.else' }) },
              ],
            };
          })(),
          try_it: {
            endpoint: 'POST /v1/check',
            body: { policy_id: 'default-action-tiers', request: { action: 'payments.send', params: { amount_usd: 20 } } },
            price_usd: c.priceUsd,
            protocol: c.free ? 'free mode' : 'x402 (USDC on Base)',
          },
          for_humans: {
            note: 'Writing these policies by hand is the slow part. The templates and the full governance pack are at the checkout below.',
            checkouts: 'GET /v1/checkouts',
          },
        },
        {},
        c.free
      );
    }

    if (request.method === 'POST' && url.pathname === '/v1/check') {
      // FREE MODE: no payment dance.
      if (c.free) {
        const out = await handleCheck(request, env, c, url);
        return out instanceof Response ? out : json(200, out.verdict, {}, true);
      }

      // PAID MODE (x402): v2 PAYMENT-SIGNATURE or v1 X-PAYMENT header.
      const payHeader = request.headers.get('payment-signature') || request.headers.get('x-payment');
      if (!payHeader) return paymentRequired402(c, url.href, url.origin);

      const payload = b64decode(payHeader);
      if (!payload) return paymentRequired402(c, url.href, url.origin, 'malformed payment header');

      // Version-pure facilitator body: v1 and v2 use different requirement schemas,
      // and CDP's validator rejects mixed dialects with a 400.
      const ver = payload.x402Version === 2 ? 2 : 1;
      const reqs = ver === 2 ? paymentRequirementsV2(c) : paymentRequirementsV1(c, url.href);
      const verifyBody = {
        x402Version: ver,
        paymentPayload: payload,
        paymentRequirements: reqs,
      };
      const verify = await facilitatorCall(env, c, 'verify', verifyBody);
      if (!verify.json || verify.json.isValid !== true) {
        return paymentRequired402(
          c,
          url.href,
          url.origin,
          `payment verification failed: ${verify.json?.invalidReason || `facilitator ${verify.status}`}`
        );
      }

      const out = await handleCheck(request, env, c, url);
      if (out instanceof Response) return out; // 4xx — do NOT settle on bad requests

      const settle = await facilitatorCall(env, c, 'settle', verifyBody);
      if (!settle.json || settle.json.success !== true) {
        return paymentRequired402(
          c,
          url.href,
          url.origin,
          `settlement failed: ${settle.json?.errorReason || `facilitator ${settle.status}`}`
        );
      }
      const receipt = b64encode(settle.json);
      return json(200, out.verdict, { 'PAYMENT-RESPONSE': receipt, 'X-PAYMENT-RESPONSE': receipt });
    }

    return json(
      404,
      { error: 'not_found', endpoints: ['POST /v1/check', 'GET /v1/policies', 'GET /healthz', 'GET /'] },
      {},
      c.free
    );
  },
};

export { check, validatePolicy, globMatch, DEFAULT_POLICY, assessReceived, readUsdcBalance, SELF_TEST_USD, GOAL_USD };
