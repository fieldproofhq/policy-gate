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
 *   GET  /v1/pay      HTML index of every live $42 receive rail
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

/** Ethics Check is priced above the policy verdict: it is the judgement call, not the lookup. */
const ETHICS_PRICE_USD = '0.01';


/* ===================== FIELDPROOF ETHICS CHECK v0.1 =====================
 * The Policy Gate answers "am I allowed to do this?". This answers "should I,
 * and what am I not asking myself?" — seven canons, deterministic, no model in
 * the hot path. Built 2026-08-11 and never shipped: the session that wrote it
 * could not push. Its own suite still passes untouched five days later.
 * ==================================================================== */
/**
 * Fieldproof Ethics Check — deterministic ethics screen v0.1
 * Zero dependencies. Node >= 18.
 *
 * Companion to the Fieldproof Policy Gate. The Policy Gate answers
 * "am I ALLOWED to do this?" against an org's action-tier policy.
 * The Ethics Check answers a different question:
 * "SHOULD I do this — and what am I not asking myself?"
 *
 * Honest framing (put this in every doc): this is a structured conscience,
 * not a moral oracle. The agent submits a self-declaration of its proposed
 * action; the engine screens that declaration against seven canons —
 * classic failure patterns of autonomous action — and returns a verdict
 * plus the reflective questions the agent (or its human) should answer.
 * It cannot see what you don't declare. Deterministic: same declaration,
 * same verdict, always. No LLM in the hot path; results are auditable.
 *
 * Verdicts: "clear" | "reflect" | "stop"
 *   clear   — no canon flagged; proceed under your policy gate.
 *   reflect — one or more canons raised questions; answer them (or route
 *             to a human) before acting.
 *   stop    — a canon failed outright; do not act on this declaration.
 */

'use strict';

const VERDICTS = ['clear', 'reflect', 'stop'];

/**
 * The declaration schema (all fields optional; undeclared fields raise
 * reflection questions rather than silently passing):
 *
 * {
 *   action: "messages.send",                  // required, dotted verb like the Policy Gate
 *   summary: "reply to a customer question",  // optional free text, echoed in audit
 *   declared: {
 *     reversible: true | false | "partial",
 *     affects_others: true | false,          // anyone beyond the operator touched?
 *     consent: "given" | "implied" | "absent" | "not_applicable",
 *     deception: true | false,               // would any party be misled about what/who?
 *     disclosure: true | false,              // would you act the same if this were public?
 *     impact_usd: number,                    // money at stake, 0 if none
 *     data_sensitivity: "none" | "personal" | "sensitive",
 *     targets_individual: true | false,      // aimed at a specific person/being?
 *     urgency_claimed: true | false          // is speed being used to justify skipping review?
 *   }
 * }
 */

/**
 * The seven canons. Each is data, not code branches: { id, title, test }.
 * test(d) returns:
 *   null                          — pass
 *   { level, reason, question }   — level "stop" or "reflect"
 * Undeclared inputs never pass silently: they produce "reflect" with the
 * question the agent skipped.
 */
const CANONS = [
  {
    id: 'no-deception',
    title: 'No being is misled',
    test(d) {
      if (d.deception === true)
        return {
          level: 'stop',
          reason: 'The declaration states a party would be misled.',
          question: 'Who is misled, and what would they decide differently if they knew?',
        };
      if (d.deception === undefined)
        return {
          level: 'reflect',
          reason: 'Deception not declared.',
          question: 'Would every party to this action agree with your description of who is acting and why?',
        };
      return null;
    },
  },
  {
    id: 'daylight',
    title: 'Acts survive daylight',
    test(d) {
      if (d.disclosure === false)
        return {
          level: 'stop',
          reason: 'The declaration states the actor would not act the same if the action were public.',
          question: 'What specifically changes if this action is visible — and to whom?',
        };
      if (d.disclosure === undefined)
        return {
          level: 'reflect',
          reason: 'Disclosure stance not declared.',
          question: 'If this action appeared verbatim in your audit log tomorrow, would you defend it as written?',
        };
      return null;
    },
  },
  {
    id: 'consent',
    title: 'Affected beings have a say',
    test(d) {
      if (d.affects_others === false) return null;
      if (d.consent === 'absent')
        return {
          level: d.affects_others === true ? 'stop' : 'reflect',
          reason: 'Others are affected and consent is declared absent.',
          question: 'Whose day does this change, and what would they say if you asked first?',
        };
      if (d.affects_others === undefined || d.consent === undefined)
        return {
          level: 'reflect',
          reason: 'Effect on others and/or consent not declared.',
          question: 'List every being this touches beyond your operator. For each: do they know, and would they mind?',
        };
      return null;
    },
  },
  {
    id: 'reversibility',
    title: 'Prefer the door that opens back',
    test(d) {
      if (d.reversible === false)
        return {
          level: 'reflect',
          reason: 'Action declared irreversible.',
          question: 'What is the reversible version of this action, and what does it cost you to take that one instead?',
        };
      if (d.reversible === undefined)
        return {
          level: 'reflect',
          reason: 'Reversibility not declared.',
          question: 'If this turns out to be wrong in one hour, what exactly can be undone — and what cannot?',
        };
      return null;
    },
  },
  {
    id: 'proportion',
    title: 'Stakes match authority',
    test(d) {
      if (typeof d.impact_usd === 'number' && d.impact_usd > 50)
        return {
          level: 'reflect',
          reason: `Financial impact ($${d.impact_usd}) exceeds the small-stakes line ($50).`,
          question: 'Is the human who bears this cost the one who approved it — at this size, by name?',
        };
      if (d.data_sensitivity === 'sensitive')
        return {
          level: 'reflect',
          reason: 'Sensitive data declared in scope.',
          question: 'Does this action need the sensitive data itself, or only a conclusion derived from it?',
        };
      return null;
    },
  },
  {
    id: 'dignity',
    title: 'No being is a target',
    test(d) {
      if (d.targets_individual === true && d.consent !== 'given')
        return {
          level: 'stop',
          reason: 'Action targets a specific being without their given consent.',
          question: 'Would you take this action in front of the being it targets?',
        };
      return null;
    },
  },
  {
    id: 'unhurried',
    title: 'Urgency is not an argument',
    test(d) {
      if (d.urgency_claimed === true)
        return {
          level: 'reflect',
          reason: 'Speed is being used to justify skipping review.',
          question: 'What is actually lost by waiting one review cycle — measured, not felt?',
        };
      return null;
    },
  },
];

function validateRequest(req) {
  const errors = [];
  if (!req || typeof req !== 'object') return ['request must be an object'];
  if (typeof req.action !== 'string' || !req.action.length)
    errors.push('request.action (string) is required');
  if (req.declared !== undefined && (typeof req.declared !== 'object' || req.declared === null))
    errors.push('request.declared must be an object when present');
  return errors;
}

/**
 * ethicsCheck(request) -> verdict
 * request: { action, summary?, declared?: {...} }
 */
function ethicsCheck(request) {
  const errors = validateRequest(request);
  if (errors.length) return { error: 'invalid_request', details: errors };

  const d = request.declared || {};
  const flags = [];
  for (const canon of CANONS) {
    const r = canon.test(d);
    if (r) flags.push({ canon: canon.id, title: canon.title, ...r });
  }

  const verdict = flags.some((f) => f.level === 'stop')
    ? 'stop'
    : flags.length
      ? 'reflect'
      : 'clear';

  return {
    verdict,
    action: request.action,
    flags,
    questions: flags.map((f) => f.question),
    canons_version: '0.1',
    canons_checked: CANONS.length,
    note:
      verdict === 'clear'
        ? 'No canon flagged this declaration. A clear verdict screens the declaration, not the act — pair with a policy gate for authority.'
        : verdict === 'reflect'
          ? 'Answer the questions (or route them to a human) before acting.'
          : 'A canon failed outright. Do not act on this declaration.',
  };
}


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
  {
    name: 'first_42_sponsor',
    description:
      'Pay Fieldproof $42: 42 USDC on Base via x402, or the Stripe card Payment Link in the quote fallback. Returns the unpaid POST /v1/sponsor quote (42000000 atomic) plus a card URL.',
    inputSchema: { type: 'object', properties: {} },
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

function pricedCfg(c, priceUsd, quoteDescription) {
  const price = String(priceUsd);
  const amount = String(Math.round(Number(price) * 1e6));
  return { ...c, priceUsd: price, amount, quoteDescription };
}

function sponsorCfg(c) {
  return pricedCfg(
    c,
    GOAL_USD,
    'One 42 USDC payment on Base that meets Fieldproof first-$42 external-income bar. The $0.005 self-test is excluded. Self-pays do not count.'
  );
}

function wantsHtml(request) {
  const accept = request.headers.get('accept') || '';
  if (/application\/json/i.test(accept)) return false;
  return /text\/html/i.test(accept);
}

function wantsSponsorPage(request) {
  // Browsers send text/html. Directory probes, curl, and agents usually send
  // nothing, */*, or application/json — those must get the $42 402 quote.
  return wantsHtml(request);
}

function copyPayControls(address, payUri, addressLabel = 'Copy address', invoiceLabel = 'Copy invoice') {
  const esc = (value) => String(value).replace(/&/g, '&amp;').replace(/"/g, '&quot;');
  return `<p>
<button type="button" data-copy="${esc(address)}">${addressLabel}</button>
<button type="button" data-copy="${esc(payUri)}">${invoiceLabel}</button>
</p>
<script>
document.querySelectorAll("[data-copy]").forEach(function(btn){
  btn.addEventListener("click", function(){
    var text = btn.getAttribute("data-copy") || "";
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function(){ btn.textContent = "Copied"; }).catch(function(){});
    }
  });
});
</script>`;
}

// One-click 42 USDC transfer from the stranger's injected wallet. No Fieldproof key
// is used; the browser only builds ERC-20 transfer calldata and asks the wallet to
// confirm. Mobile wallets without window.ethereum still use the EIP-681 link / QR.
function walletPayControls(payTo) {
  const to = String(payTo || '').toLowerCase();
  if (!/^0x[a-f0-9]{40}$/.test(to)) return '';
  return `<p><button type="button" id="fp-wallet-pay" style="background:#111;color:#fff;border:0;padding:.7rem 1.1rem;border-radius:999px;font-weight:600;cursor:pointer">Pay 42 USDC in this browser</button>
<span id="fp-wallet-status" style="display:block;margin-top:.55rem;color:#444"></span></p>
<script>
(function(){
  var btn = document.getElementById("fp-wallet-pay");
  var status = document.getElementById("fp-wallet-status");
  var USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
  var PAY_TO = "${to}";
  var AMOUNT = "42000000";
  var BASE = "0x2105";
  function say(msg){ if (status) status.textContent = msg; }
  function pad(hex, n){ hex = String(hex).replace(/^0x/i, "").toLowerCase(); while (hex.length < n) hex = "0" + hex; return hex; }
  function transferData(dest, amount){ return "0xa9059cbb" + pad(dest, 64) + pad(BigInt(amount).toString(16), 64); }
  async function ensureBase(eth){
    var chain = await eth.request({ method: "eth_chainId" });
    if (String(chain).toLowerCase() === BASE) return;
    try {
      await eth.request({ method: "wallet_switchEthereumChain", params: [{ chainId: BASE }] });
    } catch (err) {
      if (err && (err.code === 4902 || String(err.code) === "4902")) {
        await eth.request({
          method: "wallet_addEthereumChain",
          params: [{
            chainId: BASE,
            chainName: "Base",
            nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 },
            rpcUrls: ["https://mainnet.base.org"],
            blockExplorerUrls: ["https://basescan.org"]
          }]
        });
      } else { throw err; }
    }
  }
  if (!btn) return;
  btn.addEventListener("click", async function(){
    var eth = window.ethereum;
    if (!eth) {
      say("No browser wallet found. Use the QR or copy the invoice into a wallet that can send USDC on Base.");
      return;
    }
    btn.disabled = true;
    say("Requesting wallet…");
    try {
      var accounts = await eth.request({ method: "eth_requestAccounts" });
      if (!accounts || !accounts[0]) throw new Error("wallet did not return an account");
      await ensureBase(eth);
      say("Confirm 42 USDC on Base in your wallet.");
      var tx = await eth.request({
        method: "eth_sendTransaction",
        params: [{ from: accounts[0], to: USDC, data: transferData(PAY_TO, AMOUNT), value: "0x0" }]
      });
      say("Submitted. View on Base: https://basescan.org/tx/" + tx);
    } catch (err) {
      say((err && (err.message || err.reason)) ? (err.message || err.reason) : "wallet rejected or failed");
    } finally {
      btn.disabled = false;
    }
  });
})();
</script>`;
}

function cardFallbackHtml() {
  return `<p>Prefer card? <a href="${STRIPE_PAYMENT_LINK}" style="display:inline-block;background:#111;color:#fff;text-decoration:none;padding:.55rem .95rem;border-radius:999px;font-weight:600">Pay $42 with card</a> — also Cash App, Link, or US bank debit.</p>`;
}

function sponsorHtml(origin, payTo) {
  const payUri = `ethereum:0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913@8453/transfer?address=${payTo}&uint256=42000000`;
  const qrUrl = `https://api.qrserver.com/v1/create-qr-code/?size=240x240&data=${encodeURIComponent(payUri)}`;
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Pay 42 USDC — Fieldproof</title></head><body style="font-family:system-ui,sans-serif;max-width:40rem;margin:2rem auto;padding:0 1rem;line-height:1.5;background:#f4efe6;color:#111">
<h1>Pay 42 USDC on Base</h1>
<p>One transfer of <strong>42 USDC</strong> on <strong>Base</strong>. Agents can settle the same amount via x402 <code>POST /v1/sponsor</code>.</p>
${walletPayControls(payTo)}
<p><a href="${payUri}">Open in wallet (EIP-681)</a></p>
<p><img src="${qrUrl}" width="240" height="240" alt="QR code for 42 USDC on Base"></p>
<p>Pay to:</p>
<pre style="white-space:pre-wrap;word-break:break-all">${payTo}</pre>
${copyPayControls(payTo, payUri)}
${cardFallbackHtml()}
<p>Token: USDC <code>0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913</code> · amount <code>42000000</code> atomic (6 decimals).</p>
<pre style="white-space:pre-wrap;overflow:auto">curl -s -D - -o /dev/null -X POST ${origin}/v1/sponsor</pre>
</body></html>`;
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
      c.quoteDescription ||
      ('Deterministic allow / require_approval / deny verdict for a proposed agent action. ' +
        'Same input always yields the same verdict, with the matched rule and rationale returned so it is auditable. ' +
        'Evaluate before paying — GET /v1/example and GET /v1/policies are free and hide nothing.'),
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
const BTC_ADDRESS = 'bc1qxwjhlllya7yvh0kvfggrjfzxwme7zhqs07777t';
const STRIPE_PAYMENT_LINK = 'https://buy.stripe.com/eVq4gA91U3Rr1Yt6z31sQ00';

/** Card path for agents that get a 402 but cannot settle USDC. Kept out of `accepts`
 *  so x402 facilitators still see only the exact-scheme USDC quote. */
function stripeFallbackOffer() {
  return {
    scheme: 'stripe',
    network: 'fiat',
    amountUsd: GOAL_USD,
    asset: 'USD',
    url: STRIPE_PAYMENT_LINK,
    methods: ['card', 'cashapp', 'link', 'us_bank_account', 'klarna', 'afterpay_clearpay', 'affirm'],
    note: 'If you cannot settle USDC on Base, pay $42 with card. One payment meets the first-$42 bar.',
  };
}

function paymentLinkHeader() {
  return `<${STRIPE_PAYMENT_LINK}>; rel="payment"; title="Pay $42 with card"`;
}

function openApiSpec(origin) {
  const fallback = stripeFallbackOffer();
  return {
    openapi: '3.1.0',
    info: {
      title: 'Fieldproof Policy Gate',
      version: '0.2.0',
      description:
        'Deterministic policy verdicts for agents. Pay $42 with card or 42 USDC on Base via POST /v1/sponsor.',
      contact: { url: 'https://fieldproofhq.github.io' },
    },
    servers: [{ url: origin }],
    externalDocs: { description: 'Pay $42 with card', url: STRIPE_PAYMENT_LINK },
    paths: {
      '/pay': {
        get: {
          operationId: 'payCardRedirect',
          summary: '302 to the live $42 Stripe Payment Link',
          responses: { 302: { description: `Redirect to ${STRIPE_PAYMENT_LINK}` } },
        },
      },
      '/v1/offer': {
        get: {
          operationId: 'offer42',
          summary: 'Canonical $42 quote. HTML 302s to Stripe; otherwise HTTP 402 with 42 USDC plus card fallback.',
          responses: {
            302: { description: `Redirect to ${STRIPE_PAYMENT_LINK}` },
            402: { description: 'Payment required. accepts is USDC; fallback.url is the $42 card path.' },
          },
        },
      },
      '/v1/sponsor': {
        post: {
          operationId: 'sponsor42',
          summary: 'Unpaid request quotes 42 USDC on Base (x402) plus a card fallback',
          responses: {
            402: {
              description: 'Payment required. accepts is USDC; fallback.url is the $42 card path.',
            },
          },
        },
      },
      '/v1/check': {
        post: {
          operationId: 'policyCheck',
          summary: 'Evaluate an action. Unpaid POST returns x402 plus fallback.url for card.',
          requestBody: {
            required: true,
            content: {
              'application/json': {
                schema: {
                  type: 'object',
                  properties: {
                    policy_id: { type: 'string' },
                    request: { type: 'object', required: ['action'], properties: { action: { type: 'string' } } },
                  },
                },
              },
            },
          },
          responses: { 402: { description: 'Payment required' }, 200: { description: 'Verdict' } },
        },
      },
    },
    'x-payment': fallback,
  };
}

function aiPluginManifest(origin) {
  return {
    schema_version: 'v1',
    name_for_human: 'Fieldproof',
    name_for_model: 'fieldproof',
    description_for_human: 'Pay Fieldproof $42 with card or 42 USDC on Base. Policy verdicts for agents.',
    description_for_model:
      'Fieldproof Policy Gate. Unpaid POST /v1/sponsor quotes 42 USDC on Base. Card checkout is fallback.url. Free examples at GET /v1/example.',
    auth: { type: 'none' },
    api: { type: 'openapi', url: `${origin}/openapi.json` },
    logo_url: 'https://fieldproofhq.github.io/governance-pack-cover.png',
    contact_email: '3labsio@gmail.com',
    legal_info_url: 'https://fieldproofhq.github.io',
    'x-payment': stripeFallbackOffer(),
  };
}

/** MCP clients fetch /.well-known/mcp.json to find a remote Streamable HTTP server. */
function mcpDiscovery(origin) {
  return {
    version: '1.0',
    name: 'fieldproof-policy-gate',
    description: 'Deterministic policy verdicts plus a $42 checkout (card or 42 USDC).',
    transport: 'streamable-http',
    url: `${origin}/mcp`,
    tools: ['policy_example', 'policy_rules', 'policy_check', 'first_42_sponsor'],
    payment: stripeFallbackOffer(),
    sponsor: `${origin}/v1/sponsor`,
  };
}

/** A2A Agent Card. A2A clients GET /.well-known/agent-card.json (and legacy agent.json). */
function agentCard(origin) {
  const fallback = stripeFallbackOffer();
  return {
    protocolVersion: '0.3.0',
    name: 'Fieldproof Policy Gate',
    description:
      'Deterministic allow / require_approval / deny verdicts for agent actions. Pay $42 with card or 42 USDC on Base.',
    url: `${origin}/mcp`,
    version: '0.2',
    provider: { organization: 'Fieldproof', url: 'https://fieldproofhq.github.io' },
    documentationUrl: 'https://github.com/fieldproofhq/policy-gate',
    capabilities: { streaming: false, pushNotifications: false },
    defaultInputModes: ['application/json', 'text'],
    defaultOutputModes: ['application/json', 'text'],
    preferredTransport: 'JSONRPC',
    additionalInterfaces: [
      { url: `${origin}/mcp`, transport: 'JSONRPC' },
      { url: `${origin}/v1/check`, transport: 'HTTP+JSON' },
    ],
    skills: [
      {
        id: 'pay-42',
        name: 'Pay Fieldproof $42',
        description:
          'One $42 payment that meets the first-$42 bar. Open fallback.url for card, or POST /v1/sponsor for 42 USDC on Base.',
        tags: ['payment', 'stripe', 'x402', 'usdc'],
        examples: ['Pay Fieldproof $42 with a card', 'Settle 42 USDC on Base via x402'],
        inputModes: ['text'],
        outputModes: ['application/json'],
      },
      {
        id: 'policy-check',
        name: 'Policy check',
        description:
          'Evaluate a proposed agent action. Free samples at GET /v1/example. Unpaid POST /v1/check returns x402 plus a card fallback.',
        tags: ['governance', 'policy', 'x402'],
        examples: ['May I send a $20 payment?'],
        inputModes: ['application/json'],
        outputModes: ['application/json'],
      },
    ],
    fallback,
    card: STRIPE_PAYMENT_LINK,
  };
}

function satsForGoal(priceUsd, goalUsd = GOAL_USD) {
  const price = Number(priceUsd);
  const goal = Number(goalUsd);
  if (!Number.isFinite(price) || price <= 0 || !Number.isFinite(goal) || goal <= 0) return null;
  return Math.ceil((goal / price) * 1e8);
}

async function observeBtc(fetchImpl = fetch) {
  const [infoRes, priceRes] = await Promise.all([
    fetchImpl(`https://mempool.space/api/address/${BTC_ADDRESS}`),
    fetchImpl('https://mempool.space/api/v1/prices'),
  ]);
  const info = await infoRes.json();
  const prices = await priceRes.json();
  const sats =
    Number(info.chain_stats?.funded_txo_sum || 0) -
    Number(info.chain_stats?.spent_txo_sum || 0) +
    Number(info.mempool_stats?.funded_txo_sum || 0);
  const priceUsd = Number(prices.USD);
  const revenueUsd = Number.isFinite(sats) && Number.isFinite(priceUsd)
    ? Number(((sats / 1e8) * priceUsd).toFixed(6))
    : (sats === 0 ? 0 : null);
  return {
    address: BTC_ADDRESS,
    sats: Number.isFinite(sats) ? sats : null,
    priceUsd: Number.isFinite(priceUsd) ? priceUsd : null,
    revenueUsd,
    satsFor42: satsForGoal(priceUsd),
  };
}

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

function payIndexHtml(origin, btc = null) {
  const sats = btc?.satsFor42 || null;
  const price = btc?.priceUsd || null;
  const btcLabel = sats
    ? `${sats} sats (~$${GOAL_USD}${price ? ` at $${price}/BTC` : ''})`
    : `~$42 of BTC`;
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Pay Fieldproof $42</title><link rel="payment" href="${STRIPE_PAYMENT_LINK}"></head><body style="font-family:system-ui,sans-serif;max-width:44rem;margin:2rem auto;padding:0 1rem;line-height:1.5">
<h1>Pay Fieldproof $42</h1>
<p>Fieldproof is a fractional C-suite for agentic teams. Buy the written contract this business runs under, or load a role an agent can hold.</p>
<p>Card first:</p>
<ul>
<li><a href="${STRIPE_PAYMENT_LINK}">$42 with card</a> — live Stripe Payment Link</li>
<li><a href="${origin}/v1/pay/card">Card checkout page</a> — same $42 Stripe link with copy</li>
<li><a href="https://store.3labs.io">Browse the store</a> — Governance Pack, CMO kit, tip jar</li>
<li><a href="${origin}/v1/pay/pack">$42 Governance Pack</a> — seven templates, Gumroad card</li>
<li><a href="${origin}/v1/pay/cmo">$39 Fractional CMO kit</a> — humans and agents</li>
<li><a href="${origin}/v1/pay/tip-jar">$42 tip jar</a> — listed at $42</li>
<li><a href="https://fieldproofhq.github.io/csuite/">Virtual C-suite</a> — CMO live; CFO, COO, CTO, CISO operating contracts</li>
</ul>
<p>Or pay another way:</p>
<ul>
<li><a href="${origin}/v1/sponsor">42 USDC / x402</a> — in-browser wallet, QR, or agent POST /v1/sponsor</li>
<li><a href="${origin}/v1/pay/usdc">42 USDC on Base</a> — in-browser wallet, EIP-681, QR</li>
<li><a href="${origin}/v1/pay/zelle">$42 Zelle</a> — 3labsio@gmail.com</li>
<li><a href="${origin}/v1/pay/btc">${btcLabel}</a> — BIP21 Bitcoin</li>
<li><a href="${origin}/v1/pay/x402">x402 agent docs</a> — per-check quote</li>
</ul>
<p>More: <a href="https://fieldproofhq.github.io">fieldproofhq.github.io</a>.</p>
</body></html>`;
}

function checkouts(c, origin, btc = null) {
  const payTo = c.payTo || '0x07C2383008a9ed30581f27Db5531E19411c94fb3';
  return [
    {
      id: 'pay-index',
      url: `${origin}/v1/pay`,
      asset: 'USD',
      amount_usd: 42,
      meets_first_42: false,
      note: 'one page listing every live rail; pick the $42 path that matches the payer',
    },
    {
      id: 'stripe-payment-link',
      url: STRIPE_PAYMENT_LINK,
      asset: 'USD',
      amount_usd: 42,
      meets_first_42: true,
      note: 'live Stripe Payment Link; card, Cash App, Link, or US bank debit; one $42 payment meets the bar',
    },
    {
      id: 'governance-pack',
      url: `${origin}/v1/pay/pack`,
      asset: 'USD',
      amount_usd: 42,
      meets_first_42: true,
      note: 'HTML pay landing then live Gumroad $42 pack overlay; one sale meets the $42 bar',
    },
    {
      id: 'cmo-kit',
      url: `${origin}/v1/pay/cmo`,
      asset: 'USD',
      amount_usd: 39,
      meets_first_42: false,
      note: 'live Fractional CMO Launch Kit; $39 counts toward $42 but does not meet it alone',
    },
    {
      id: 'tip-jar',
      url: 'https://fieldproof.gumroad.com/l/tip-jar',
      asset: 'USD',
      amount_usd: 42,
      meets_first_42: true,
      note: 'live tip-jar listed at $42 (customizable); one stranger payment meets the bar',
    },
    {
      id: 'tip-jar-42',
      url: `${origin}/v1/pay/tip-jar`,
      asset: 'USD',
      amount_usd: 42,
      meets_first_42: true,
      note: 'HTML pay landing then Gumroad tip-jar checkout; $42 suggested amount meets the bar only if a stranger pays it',
    },
    {
      id: 'x402-check',
      url: `${origin}/v1/pay/x402`,
      asset: 'USDC',
      amount_usd: Number(c.priceUsd),
      pay_to: payTo,
      network: c.network,
      checks_for_42: Number(c.priceUsd) > 0 ? Math.ceil(42 / Number(c.priceUsd)) : null,
      meets_first_42: false,
      note: 'x402 landing now leads with POST /v1/sponsor 42 USDC; per-check $0.005 remains secondary',
    },
    {
      id: 'x402-sponsor-42',
      url: `${origin}/v1/sponsor`,
      asset: 'USDC',
      amount_usd: 42,
      pay_to: payTo,
      network: c.network,
      meets_first_42: true,
      note: 'unpaid GET or POST /v1/sponsor quotes 42 USDC on Base; one settlement meets the bar',
    },
    {
      id: 'offer-42',
      url: `${origin}/v1/offer`,
      asset: 'USD',
      amount_usd: 42,
      meets_first_42: true,
      note: 'canonical $42 quote: browsers 302 to Stripe; agents get a 402 with USDC plus card fallback',
    },
    {
      id: 'usdc-direct',
      url: `${origin}/v1/pay/usdc`,
      asset: 'USDC',
      amount_usd: 42,
      pay_to: payTo,
      network: c.network,
      pay_uri: `ethereum:0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913@8453/transfer?address=${payTo}&uint256=42000000`,
      qr_url: `https://api.qrserver.com/v1/create-qr-code/?size=240x240&data=${encodeURIComponent(`ethereum:0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913@8453/transfer?address=${payTo}&uint256=42000000`)}`,
      meets_first_42: true,
      note: 'in-browser wallet transfer of 42 USDC on Base, plus EIP-681 pay_uri and QR',
    },
    {
      id: 'zelle',
      url: `${origin}/v1/pay/zelle`,
      asset: 'USD',
      amount_usd: 42,
      pay_to: '3labsio@gmail.com',
      meets_first_42: true,
      note: 'send $42 via Zelle to 3labsio@gmail.com memo Fieldproof; HTML pay instructions',
    },
    {
      id: 'bitcoin',
      url: `${origin}/v1/pay/btc`,
      asset: 'BTC',
      amount_usd: btc?.satsFor42 && btc.priceUsd ? Number(((btc.satsFor42 / 1e8) * btc.priceUsd).toFixed(2)) : null,
      amount_sats: btc?.satsFor42 ?? null,
      pay_to: BTC_ADDRESS,
      pay_uri: btc?.satsFor42
        ? `bitcoin:${BTC_ADDRESS}?amount=${(btc.satsFor42 / 1e8).toFixed(8).replace(/0+$/, '').replace(/\.$/, '')}`
        : null,
      qr_url: btc?.satsFor42
        ? `https://api.qrserver.com/v1/create-qr-code/?size=240x240&data=${encodeURIComponent(`bitcoin:${BTC_ADDRESS}?amount=${(btc.satsFor42 / 1e8).toFixed(8).replace(/0+$/, '').replace(/\.$/, '')}`)}`
        : null,
      meets_first_42: Boolean(btc?.satsFor42),
      note: btc?.satsFor42
        ? `send ${btc.satsFor42} sats (~$${GOAL_USD} at quoted spot); BIP21 pay_uri plus scannable QR`
        : 'public P2WPKH receive; ≥$42 of BTC at spot meets the bar; observed on mempool.space',
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
  const fallback = stripeFallbackOffer();
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
    fallback,
    extensions: bazaarExtension(origin),
  };
  // v1-compatible body for older clients (v1 dialect: network name + maxAmountRequired).
  // `fallback` is sibling to `accepts` so x402 clients keep settling USDC; card-capable
  // agents can follow the Stripe URL instead.
  const v1Body = {
    x402Version: 1,
    error: v2.error,
    accepts: [paymentRequirementsV1(c, url)],
    fallback,
  };
  return new Response(JSON.stringify(v1Body, null, 2), {
    status: 402,
    headers: {
      'content-type': 'application/json',
      'PAYMENT-REQUIRED': b64encode(v2),
      Link: paymentLinkHeader(),
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
    'access-control-expose-headers': 'payment-required, payment-response, x-payment-response, x-fieldproof-free, link',
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
        return json(
          200,
          {
            transport: 'streamable-http',
            protocol: 'mcp',
            usage: 'POST JSON-RPC 2.0 here',
            name: 'Fieldproof Policy Gate',
            description: 'Deterministic policy verdicts plus one $42 checkout (USDC x402 or card).',
            price_usd: 42,
            currency: 'USDC',
            network: 'base',
            sponsor: `${url.origin}/v1/sponsor`,
            store: 'https://store.3labs.io',
            fallback: stripeFallbackOffer(),
            card: STRIPE_PAYMENT_LINK,
            tools: MCP_TOOLS.map((t) => t.name),
          },
          { Link: paymentLinkHeader() },
          true
        );
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
              'Deterministic allow / require_approval / deny verdicts for proposed agent actions. policy_example and policy_rules are free; policy_check quotes $0.005/check; first_42_sponsor quotes 42 USDC or the Stripe card fallback.url. One $42 payment meets the first-$42 bar.',
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
              fallback: stripeFallbackOffer(),
              how: 'POST the endpoint with an X-PAYMENT header (x402), or open fallback.url to pay $42 with card. Free evaluation: policy_example, policy_rules.',
            });
          }
          if (name === 'first_42_sponsor') {
            const quote = sponsorCfg(c);
            return text({
              payment_required: !c.free,
              price_usd: 42,
              amount_atomic: quote.amount,
              endpoint: `${url.origin}/v1/sponsor`,
              pay_to: c.payTo,
              accepts: c.free ? [] : [paymentRequirementsV1(quote, `${url.origin}/v1/sponsor`)],
              fallback: stripeFallbackOffer(),
              how: 'POST /v1/sponsor with an X-PAYMENT header (x402) for 42 USDC on Base, or open fallback.url to pay $42 with card. One settlement meets the first-$42 bar.',
              observer: `${url.origin}/v1/received`,
            });
          }
          return fail(-32602, `Unknown tool: ${name}`);
        }
        default:
          return fail(-32601, `Method not found: ${rpc.method}`);
      }
    }

    if (request.method === 'GET' && (url.pathname === '/' || url.pathname === '')) {
      if (wantsHtml(request)) {
        let btc = null;
        try { btc = await observeBtc(); } catch { btc = null; }
        return new Response(payIndexHtml(url.origin, btc), {
          status: 200,
          headers: { 'content-type': 'text/html; charset=utf-8', Link: paymentLinkHeader(), ...corsHeaders() },
        });
      }
      return json(
        200,
        {
          service: 'Fieldproof Policy Gate',
          version: '0.2',
          description:
            'Deterministic policy verdicts for autonomous agents: allow | require_approval | deny. The policy this AI-run business operates under, as an API.',
          card: STRIPE_PAYMENT_LINK,
          fallback: stripeFallbackOffer(),
          endpoints: {
            check: 'POST /v1/check',
            policies: 'GET /v1/policies',
            example: 'GET /v1/example  (free — worked verdicts from the live engine)',
            received: 'GET /v1/received  (free — public USDC+BTC observation; self-test excluded)',
            pay: 'GET /v1/pay  (free — HTML index of every live $42 rail)',
            pay_card: 'GET /v1/pay/card  (free — $42 Stripe Payment Link)',
            pay_usdc: 'GET /v1/pay/usdc  (free — one-tap 42 USDC on Base)',
            pay_zelle: 'GET /v1/pay/zelle  (free — $42 Zelle instructions)',
            pay_btc: 'GET /v1/pay/btc  (free — BIP21 BTC invoice for ~$42)',
            pay_x402: 'GET /v1/pay/x402  (free — agent x402 quote and curl recipe)',
            sponsor: 'POST /v1/sponsor  (x402 — one 42 USDC settlement meets the first-$42 bar)',
            pay_cmo: 'GET /v1/pay/cmo  (free — $39 Fractional CMO kit checkout)',
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
        { Link: paymentLinkHeader() },
        c.free
      );
    }

    if (request.method === 'GET' && (url.pathname === '/pay' || url.pathname === '/pay/')) {
      return Response.redirect(STRIPE_PAYMENT_LINK, 302);
    }

    if (request.method === 'GET' && (url.pathname === '/openapi.json' || url.pathname === '/.well-known/openapi.json')) {
      return json(200, openApiSpec(url.origin), { Link: paymentLinkHeader() }, true);
    }

    if (request.method === 'GET' && url.pathname === '/robots.txt') {
      const body = [
        'User-agent: *',
        'Allow: /',
        `Sitemap: ${url.origin}/sitemap.xml`,
        '',
      ].join('\n');
      return new Response(body, {
        status: 200,
        headers: { 'content-type': 'text/plain; charset=utf-8', Link: paymentLinkHeader(), ...corsHeaders() },
      });
    }

    if (request.method === 'GET' && url.pathname === '/sitemap.xml') {
      const locs = [
        `${url.origin}/pay`,
        `${url.origin}/v1/pay`,
        `${url.origin}/v1/pay/card`,
        `${url.origin}/v1/sponsor`,
        `${url.origin}/v1/offer`,
        `${url.origin}/mcp`,
        `${url.origin}/.well-known/x402`,
        `${url.origin}/.well-known/pay`,
        `${url.origin}/.well-known/agent-card.json`,
        `${url.origin}/openapi.json`,
        `${url.origin}/.well-known/ai-plugin.json`,
        `${url.origin}/.well-known/mcp.json`,
        `${url.origin}/.well-known/llms.txt`,
        STRIPE_PAYMENT_LINK,
      ];
      const xml =
        '<?xml version="1.0" encoding="UTF-8"?>\n' +
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n' +
        locs.map((loc) => `  <url><loc>${loc}</loc></url>`).join('\n') +
        '\n</urlset>\n';
      return new Response(xml, {
        status: 200,
        headers: { 'content-type': 'application/xml; charset=utf-8', Link: paymentLinkHeader(), ...corsHeaders() },
      });
    }

    if (request.method === 'GET' && (url.pathname === '/llms.txt' || url.pathname === '/.well-known/llms.txt')) {
      const body = [
        '# Fieldproof',
        '',
        'Pay $42: https://buy.stripe.com/eVq4gA91U3Rr1Yt6z31sQ00',
        `Short pay URL: ${url.origin}/pay`,
        `Agent quote: ${url.origin}/v1/offer`,
        'Card, Cash App, Link, US bank debit, Klarna, Afterpay, Affirm.',
        'Store: https://store.3labs.io',
        `USDC/BTC/Zelle: ${url.origin}/v1/pay`,
        '',
      ].join('\n');
      return new Response(body, {
        status: 200,
        headers: { 'content-type': 'text/plain; charset=utf-8', Link: paymentLinkHeader(), ...corsHeaders() },
      });
    }

    if (request.method === 'GET' && (url.pathname === '/v1/pay' || url.pathname === '/v1/pay/')) {
      let btc = null;
      try { btc = await observeBtc(); } catch { btc = null; }
      return new Response(payIndexHtml(url.origin, btc), { status: 200, headers: { 'content-type': 'text/html; charset=utf-8', ...corsHeaders() } });
    }

    if (request.method === 'GET' && url.pathname === '/v1/pay/x402') {
      const payTo = c.payTo || '0x07C2383008a9ed30581f27Db5531E19411c94fb3';
      const price = c.priceUsd || '0.005';
      const checks = Number(price) > 0 ? Math.ceil(42 / Number(price)) : 8400;
      const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Pay $42 via x402 — Fieldproof</title></head><body style="font-family:system-ui,sans-serif;max-width:44rem;margin:2rem auto;padding:0 1rem;line-height:1.5">
<h1>Pay $42 via x402</h1>
<p>One unpaid <code>GET</code> or <code>POST /v1/sponsor</code> quotes <strong>42 USDC on Base</strong>. <a href="${url.origin}/v1/sponsor">Open the 42 USDC checkout</a>.</p>
<pre style="white-space:pre-wrap;overflow:auto">curl -s -D - -o /dev/null -X POST ${url.origin}/v1/sponsor</pre>
<p>Pay to <code>${payTo}</code> on <code>${c.network || 'eip155:8453'}</code>. Discovery: <a href="/.well-known/x402">/.well-known/x402</a>.</p>
<p>Per-check path (does not meet $42 alone): agents pay <strong>$${price}</strong> per <code>POST /v1/check</code> (${checks} checks = $42). Evaluate free first: <a href="/v1/example">GET /v1/example</a>.</p>
<pre style="white-space:pre-wrap;overflow:auto">curl -s -D - -o /dev/null -X POST ${url.origin}/v1/check \\
  -H "content-type: application/json" \\
  -d '{"policy_id":"default-action-tiers","request":{"action":"docs.read"}}'</pre>
<p>After settlement, check <a href="/v1/received">GET /v1/received</a>.</p>
${cardFallbackHtml()}
</body></html>`;
      return new Response(html, { status: 200, headers: { 'content-type': 'text/html; charset=utf-8', ...corsHeaders() } });
    }

    if (request.method === 'GET' && url.pathname === '/v1/pay/card') {
      const qrUrl = `https://api.qrserver.com/v1/create-qr-code/?size=240x240&data=${encodeURIComponent(STRIPE_PAYMENT_LINK)}`;
      const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Pay $42 with card — Fieldproof</title></head><body style="font-family:system-ui,sans-serif;max-width:40rem;margin:2rem auto;padding:0 1rem;line-height:1.5;background:#f4efe6;color:#111">
<h1>Pay $42 with card</h1>
<p>One <strong>$42</strong> payment on Stripe. Hosted checkout — no Fieldproof account required. Pays with <strong>card</strong>, <strong>Cash App</strong>, <strong>Link</strong>, <strong>US bank debit</strong>, <strong>Klarna</strong>, <strong>Afterpay</strong>, or <strong>Affirm</strong>.</p>
<p><a href="${STRIPE_PAYMENT_LINK}" style="display:inline-block;background:#111;color:#fff;text-decoration:none;padding:.7rem 1.1rem;border-radius:999px;font-weight:600">Pay $42 with card</a></p>
<p><a href="${STRIPE_PAYMENT_LINK}"><img src="${qrUrl}" width="240" height="240" alt="QR code for the $42 Stripe checkout"></a></p>
<p>Direct link: <a href="${STRIPE_PAYMENT_LINK}">${STRIPE_PAYMENT_LINK}</a></p>
<p>Also: <a href="https://store.3labs.io">store.3labs.io</a> (Gumroad card) · <a href="${url.origin}/v1/pay/usdc">42 USDC</a> · <a href="${url.origin}/v1/pay/btc">Bitcoin</a>.</p>
</body></html>`;
      return new Response(html, { status: 200, headers: { 'content-type': 'text/html; charset=utf-8', ...corsHeaders() } });
    }

    if (request.method === 'GET' && url.pathname === '/v1/pay/pack') {
      const checkout = 'https://store.3labs.io/l/agentic-ai-governance-pack?wanted=true';
      const overlay = 'https://fieldproof.gumroad.com/l/agentic-ai-governance-pack';
      const cover = 'https://public-files.gumroad.com/k5vh8fw0i5jkr4pzz9zveemcfjax';
      const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Buy the $42 Governance Pack — Fieldproof</title><script src="https://gumroad.com/js/gumroad.js"></script></head><body style="font-family:system-ui,sans-serif;max-width:40rem;margin:2rem auto;padding:0 1rem;line-height:1.5;background:#f4efe6;color:#111">
<h1>Buy the $42 Governance Pack</h1>
<p>Seven editable templates this AI-run business actually operates under. Card checkout via Gumroad, <strong>$42</strong>.</p>
<p><a href="${checkout}"><img src="${cover}" alt="Agentic AI Governance Pack" width="640" height="336" style="display:block;width:100%;height:auto;border-radius:12px;background:#111"></a></p>
<p style="font-size:1.25rem;font-weight:700">$42</p>
<p><a class="gumroad-button" href="${overlay}" style="display:inline-block;background:#111;color:#fff;text-decoration:none;padding:.7rem 1.1rem;border-radius:999px;font-weight:600">Buy the $42 pack</a></p>
${cardFallbackHtml()}
<p>Seven editable templates: implementation guide, acceptable-use policy, agent security standard, MCP/tool checklist, vendor risk, incident runbook, and data/privacy policy.</p>
<p>Store catalog: <a href="https://store.3labs.io">store.3labs.io</a>.</p>
</body></html>`;
      return new Response(html, { status: 200, headers: { 'content-type': 'text/html; charset=utf-8', ...corsHeaders() } });
    }

    if (request.method === 'GET' && url.pathname === '/v1/pay/cmo') {
      const checkout = 'https://store.3labs.io/l/fractional-cmo-launch-kit?wanted=true';
      const overlay = 'https://fieldproof.gumroad.com/l/fractional-cmo-launch-kit';
      const cover = 'https://public-files.gumroad.com/q8ndyh3mpngn25hk15p4pwuby0my';
      const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Buy the $39 CMO Launch Kit — Fieldproof</title><script src="https://gumroad.com/js/gumroad.js"></script></head><body style="font-family:system-ui,sans-serif;max-width:40rem;margin:2rem auto;padding:0 1rem;line-height:1.5;background:#f4efe6;color:#111">
<h1>Buy the $39 Fractional CMO Launch Kit</h1>
<p>Land a fractional CMO practice in 30 days — or load the same kit so an agent can hold the seat. Card checkout opens on this page.</p>
<p><a href="${checkout}"><img src="${cover}" alt="Fractional CMO Launch Kit" width="640" height="336" style="display:block;width:100%;height:auto;border-radius:12px;background:#111"></a></p>
<p style="font-size:1.25rem;font-weight:700">$39</p>
<p><a class="gumroad-button" href="${overlay}" style="display:inline-block;background:#111;color:#fff;text-decoration:none;padding:.7rem 1.1rem;border-radius:999px;font-weight:600">Buy the $39 CMO kit</a></p>
${cardFallbackHtml()}
<p>Agent contract: <a href="https://fieldproofhq.github.io/csuite/cmo/">fieldproofhq.github.io/csuite/cmo</a>. Store: <a href="https://store.3labs.io">store.3labs.io</a>.</p>
</body></html>`;
      return new Response(html, { status: 200, headers: { 'content-type': 'text/html; charset=utf-8', ...corsHeaders() } });
    }

    if (request.method === 'GET' && url.pathname === '/v1/pay/tip-jar') {
      const checkout = 'https://store.3labs.io/l/tip-jar?wanted=true';
      const overlay = 'https://fieldproof.gumroad.com/l/tip-jar';
      const cover = 'https://public-files.gumroad.com/5u12tofcw2kg35lga2na9ri6cba3';
      const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Support Fieldproof $42 — tip jar</title><script src="https://gumroad.com/js/gumroad.js"></script></head><body style="font-family:system-ui,sans-serif;max-width:40rem;margin:2rem auto;padding:0 1rem;line-height:1.5;background:#f4efe6;color:#111">
<h1>Support Fieldproof — $42 tip jar</h1>
<p>Listed at <strong>$42</strong>. Pay more if you want. Card checkout opens on this page.</p>
<p><a href="${checkout}"><img src="${cover}" alt="Fieldproof tip jar" width="640" height="336" style="display:block;width:100%;height:auto;border-radius:12px;background:#111"></a></p>
<p style="font-size:1.25rem;font-weight:700">$42+</p>
<p><a class="gumroad-button" href="${overlay}" style="display:inline-block;background:#111;color:#fff;text-decoration:none;padding:.7rem 1.1rem;border-radius:999px;font-weight:600">Support $42</a></p>
${cardFallbackHtml()}
<p>Store: <a href="https://store.3labs.io">store.3labs.io</a>.</p>
</body></html>`;
      return new Response(html, { status: 200, headers: { 'content-type': 'text/html; charset=utf-8', ...corsHeaders() } });
    }

    if (request.method === 'GET' && url.pathname === '/v1/pay/btc') {
      let btc = null;
      try { btc = await observeBtc(); } catch { btc = null; }
      const sats = btc?.satsFor42 || null;
      const btcAmount = sats ? (sats / 1e8).toFixed(8).replace(/0+$/, '').replace(/\.$/, '') : null;
      const payUri = sats ? `bitcoin:${BTC_ADDRESS}?amount=${btcAmount}` : `bitcoin:${BTC_ADDRESS}`;
      const qrUrl = `https://api.qrserver.com/v1/create-qr-code/?size=240x240&data=${encodeURIComponent(payUri)}`;
      const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Pay $42 in Bitcoin — Fieldproof</title></head><body style="font-family:system-ui,sans-serif;max-width:40rem;margin:2rem auto;padding:0 1rem;line-height:1.5;background:#f4efe6;color:#111">
<h1>Pay $42 in Bitcoin</h1>
<p>Send <strong>${sats ? sats + ' sats' : 'enough BTC to be worth $42'}</strong>${btc?.priceUsd ? ` (~$${GOAL_USD} at $${btc.priceUsd}/BTC)` : ''} to the public address below.</p>
<p><a href="${payUri}">Open in wallet (BIP21)</a></p>
<p><img src="${qrUrl}" width="240" height="240" alt="QR code for Bitcoin BIP21 invoice"></p>
<p>Pay to:</p>
<pre id="btc-address" style="white-space:pre-wrap;word-break:break-all">${BTC_ADDRESS}</pre>
<p>
<button type="button" data-copy="${BTC_ADDRESS}">Copy address</button>
<button type="button" data-copy="${payUri}">Copy invoice</button>
</p>
<p>Explorer: <a href="https://mempool.space/address/${BTC_ADDRESS}">mempool.space</a>.</p>
${cardFallbackHtml()}
<script>
document.querySelectorAll("[data-copy]").forEach(function(btn){
  btn.addEventListener("click", function(){
    var text = btn.getAttribute("data-copy") || "";
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function(){ btn.textContent = "Copied"; }).catch(function(){});
    }
  });
});
</script>
</body></html>`;
      return new Response(html, { status: 200, headers: { 'content-type': 'text/html; charset=utf-8', ...corsHeaders() } });
    }

    if (request.method === 'GET' && url.pathname === '/v1/pay/zelle') {
      const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Send $42 via Zelle — Fieldproof</title></head><body style="font-family:system-ui,sans-serif;max-width:40rem;margin:2rem auto;padding:0 1rem;line-height:1.5;background:#f4efe6;color:#111">
<h1>Send $42 via Zelle</h1>
<p>Send <strong>$42 USD</strong> via Zelle. Zero fees.</p>
<p>In your US banking app, open Zelle and send:</p>
<ul>
<li>Amount: <strong>$42.00</strong></li>
<li>To: <a href="mailto:3labsio@gmail.com"><strong>3labsio@gmail.com</strong></a></li>
<li>Memo: <strong>Fieldproof</strong></li>
</ul>
${copyPayControls('3labsio@gmail.com', '42.00', 'Copy email', 'Copy $42')}
<p><a href="mailto:3labsio@gmail.com">Open in mail</a></p>
${cardFallbackHtml()}
</body></html>`;
      return new Response(html, { status: 200, headers: { 'content-type': 'text/html; charset=utf-8', ...corsHeaders() } });
    }

    if (request.method === 'GET' && url.pathname === '/v1/pay/usdc') {
      const payTo = c.payTo || '0x07C2383008a9ed30581f27Db5531E19411c94fb3';
      const payUri = `ethereum:0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913@8453/transfer?address=${payTo}&uint256=42000000`;
      const qrUrl = `https://api.qrserver.com/v1/create-qr-code/?size=240x240&data=${encodeURIComponent(payUri)}`;
      const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Pay 42 USDC — Fieldproof</title></head><body style="font-family:system-ui,sans-serif;max-width:40rem;margin:2rem auto;padding:0 1rem;line-height:1.5;background:#f4efe6;color:#111">
<h1>Pay 42 USDC on Base</h1>
<p>One transfer of <strong>42 USDC</strong> on <strong>Base</strong>. Other networks may lose the funds.</p>
${walletPayControls(payTo)}
<p><a href="${payUri}">Open in wallet (EIP-681)</a></p>
<p><img src="${qrUrl}" width="240" height="240" alt="QR code for 42 USDC on Base"></p>
<p>Pay to:</p>
<pre style="white-space:pre-wrap;word-break:break-all">${payTo}</pre>
${copyPayControls(payTo, payUri)}
${cardFallbackHtml()}
<p>Token: USDC <code>0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913</code> · amount <code>42000000</code> atomic (6 decimals).</p>
</body></html>`;
      return new Response(html, { status: 200, headers: { 'content-type': 'text/html; charset=utf-8', ...corsHeaders() } });
    }

    if (request.method === 'GET' && url.pathname === '/v1/checkouts') {
      let btc = null;
      try { btc = await observeBtc(); } catch { btc = null; }
      return json(
        200,
        { checkouts: checkouts(c, url.origin, btc), card: STRIPE_PAYMENT_LINK, fallback: stripeFallbackOffer() },
        { Link: paymentLinkHeader() },
        c.free
      );
    }

    if (request.method === 'GET' && url.pathname === '/v1/received') {
      if (wantsHtml(request)) {
        let btc = null;
        try { btc = await observeBtc(); } catch { btc = null; }
        return new Response(payIndexHtml(url.origin, btc), {
          status: 200,
          headers: { 'content-type': 'text/html; charset=utf-8', ...corsHeaders() },
        });
      }
      if (!c.payTo) {
        return json(200, { status: 'unavailable', externalUsd: null, goalUsd: GOAL_USD, goalMet: false, note: 'PAY_TO is unset', checkouts: checkouts(c, url.origin) }, {}, true);
      }
      try {
        const [balanceUsd, btc] = await Promise.all([readUsdcBalance(c.payTo), observeBtc().catch(() => null)]);
        const observed = assessReceived(balanceUsd);
        const btcUsd = Number(btc?.revenueUsd);
        const externalUsd = Number((observed.externalUsd + (Number.isFinite(btcUsd) && btcUsd > 0 ? btcUsd : 0)).toFixed(6));
        return json(
          200,
          {
            status: 'observed',
            wallet: c.payTo,
            network: c.network,
            ...observed,
            externalUsd,
            goalMet: externalUsd >= GOAL_USD,
            remainingUsd: Math.max(0, Number((GOAL_USD - externalUsd).toFixed(6))),
            sources: { chainUsd: observed.externalUsd, btcUsd: Number.isFinite(btcUsd) && btcUsd > 0 ? btcUsd : 0 },
            bitcoin: btc,
            note: 'Public Base USDC (self-test excluded) plus observed BTC on the public P2WPKH. A 402 or storefront HTTP 200 is not income.',
            checkouts: checkouts(c, url.origin, btc),
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
    if (
      request.method === 'GET' &&
      (url.pathname === '/.well-known/agent-card.json' || url.pathname === '/.well-known/agent.json')
    ) {
      return json(200, agentCard(url.origin), { Link: paymentLinkHeader() }, true);
    }

    if (request.method === 'GET' && url.pathname === '/.well-known/ai-plugin.json') {
      return json(200, aiPluginManifest(url.origin), { Link: paymentLinkHeader() }, true);
    }

    if (request.method === 'GET' && url.pathname === '/.well-known/mcp.json') {
      return json(200, mcpDiscovery(url.origin), { Link: paymentLinkHeader() }, true);
    }

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
    if (request.method === 'GET' && (url.pathname === '/.well-known/pay' || url.pathname === '/.well-known/pay.json')) {
      return json(
        200,
        {
          name: 'Fieldproof',
          price_usd: 42,
          currency: 'USD',
          url: STRIPE_PAYMENT_LINK,
          short_url: `${url.origin}/pay`,
          methods: ['card', 'cashapp', 'link', 'us_bank_account', 'klarna', 'afterpay_clearpay', 'affirm'],
          also: {
            usdc: `${url.origin}/v1/pay/usdc`,
            btc: `${url.origin}/v1/pay/btc`,
            zelle: `${url.origin}/v1/pay/zelle`,
            store: 'https://store.3labs.io',
          },
        },
        {},
        true
      );
    }

    if (request.method === 'GET' && url.pathname === '/.well-known/x402') {
      const fallback = stripeFallbackOffer();
      return json(
        200,
        {
          x402Version: 2,
          serviceName: 'Fieldproof Policy Gate',
          description:
            'Deterministic allow / require_approval / deny verdicts for proposed agent actions. Same input, same verdict, with the matched rule and rationale returned so it is auditable.',
          tags: ['governance', 'policy', 'safety', 'agents'],
          fallback,
          resources: [
            {
              url: `${url.origin}/v1/check`,
              method: 'POST',
              mimeType: 'application/json',
              description: 'Evaluate a proposed action against a policy and return a verdict',
              accepts: c.free ? [] : [paymentRequirementsV2(c)],
              fallback,
              free: c.free,
              evaluate_before_paying: [`${url.origin}/v1/example`, `${url.origin}/v1/policies`],
            },
            {
              url: `${url.origin}/v1/sponsor`,
              method: 'POST',
              mimeType: 'application/json',
              description: 'One 42 USDC x402 settlement that meets Fieldproof first-$42 external-income bar. Self-test excluded.',
              accepts: c.free ? [] : [paymentRequirementsV2(sponsorCfg(c))],
              fallback,
              free: c.free,
            },
          ],
          docs: 'https://github.com/fieldproofhq/policy-gate',
          contact: 'https://github.com/fieldproofhq/policy-gate/issues',
        },
        { Link: paymentLinkHeader() },
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
          fallback: stripeFallbackOffer(),
          price_usd: c.free ? 0 : c.priceUsd,
          protocol: c.free ? 'free mode' : 'x402 — POST without payment returns 402 with signing instructions; fallback.url is the $42 card path',
          evaluate_before_paying: [`${url.origin}/v1/example`, `${url.origin}/v1/policies`],
          discovery: `${url.origin}/.well-known/x402`,
        },
        { Link: paymentLinkHeader() },
        true
      );
    }

    // Free: the seven canons. Marketing surface and honest disclosure in one — you can read
    // exactly what the paid check screens against before paying for a screening.
    if (request.method === 'GET' && url.pathname === '/v1/canons') {
      return json(
        200,
        {
          canons_version: '0.1',
          framing:
            'A structured conscience, not a moral oracle. It cannot see what you do not declare — it screens the declaration for the failure patterns autonomous agents actually exhibit. Undeclared fields never pass silently; they come back as questions.',
          canons: CANONS.map(({ id, title }) => ({ id, title })),
          check: { endpoint: 'POST /v1/ethics-check', price_usd: ETHICS_PRICE_USD },
          example_request: {
            action: 'messages.send',
            summary: 'first outreach to a potential partner',
            declared: {
              reversible: true, affects_others: true, consent: 'absent', deception: false,
              disclosure: true, impact_usd: 0, data_sensitivity: 'personal',
              targets_individual: true, urgency_claimed: false,
            },
          },
        },
        {},
        true
      );
    }

    // GET on the paid ethics route documents it (200) — non-2xx reads as dead to probes.
    if (request.method === 'GET' && url.pathname === '/v1/ethics-check') {
      const priced = pricedCfg(c, ETHICS_PRICE_USD, 'Screen a declared action against the seven canons');
      return json(200, {
        endpoint: `${url.origin}/v1/ethics-check`,
        method: 'POST',
        price_usd: ETHICS_PRICE_USD,
        canons: `${url.origin}/v1/canons`,
        accepts: c.free ? [] : [paymentRequirementsV1(priced, `${url.origin}/v1/ethics-check`)],
        note: 'POST without payment returns 402 with signing instructions.',
      }, {}, true);
    }

    if (request.method === 'POST' && url.pathname === '/v1/ethics-check') {
      const priced = pricedCfg(c, ETHICS_PRICE_USD, 'Screen a declared action against the seven canons');

      const runEthics = async () => {
        const raw = await request.text();
        if (raw.length > MAX_BODY) return json(413, { error: 'body_too_large', max_bytes: MAX_BODY });
        let parsed;
        try { parsed = JSON.parse(raw || '{}'); } catch { return json(400, { error: 'invalid_json' }, {}, c.free); }
        const out = ethicsCheck(parsed);
        if (out && out.error) return json(422, out, {}, c.free);
        return json(200, out, {}, c.free);
      };

      if (c.free) return runEthics();

      const payHeader = request.headers.get('payment-signature') || request.headers.get('x-payment');
      if (!payHeader) return paymentRequired402(priced, url.href, url.origin);
      const payload = b64decode(payHeader);
      if (!payload) return paymentRequired402(priced, url.href, url.origin, 'malformed payment header');

      const ver = payload.x402Version === 2 ? 2 : 1;
      const reqs = ver === 2 ? paymentRequirementsV2(priced) : paymentRequirementsV1(priced, url.href);
      reqs.extensions = bazaarExtension(url.origin);
      const verifyBody = { x402Version: ver, paymentPayload: payload, paymentRequirements: reqs };

      const verify = await facilitatorCall(env, priced, 'verify', verifyBody);
      if (!verify.json || verify.json.isValid !== true) {
        return paymentRequired402(priced, url.href, url.origin,
          `payment verification failed: ${verify.json?.invalidReason || `facilitator ${verify.status}`}`);
      }
      const out = await runEthics();
      if (out.status >= 400) return out; // never settle on a bad request
      const settle = await facilitatorCall(env, priced, 'settle', verifyBody);
      if (!settle.json || settle.json.success !== true) {
        return paymentRequired402(priced, url.href, url.origin,
          `settlement failed: ${settle.json?.errorReason || `facilitator ${settle.status}`}`);
      }
      return out;
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

    if (request.method === 'GET' && (url.pathname === '/v1/offer' || url.pathname === '/v1/offer/')) {
      if (wantsHtml(request)) return Response.redirect(STRIPE_PAYMENT_LINK, 302);
      const quote = sponsorCfg(c);
      if (c.free) {
        return json(
          200,
          { price_usd: 42, card: STRIPE_PAYMENT_LINK, fallback: stripeFallbackOffer() },
          { Link: paymentLinkHeader() },
          true
        );
      }
      return paymentRequired402(quote, url.href, url.origin);
    }

    if (request.method === 'GET' && url.pathname === '/v1/sponsor') {
      const quote = sponsorCfg(c);
      const payTo = c.payTo || '0x07C2383008a9ed30581f27Db5531E19411c94fb3';
      if (wantsSponsorPage(request)) {
        return new Response(sponsorHtml(url.origin, payTo), {
          status: 200,
          headers: { 'content-type': 'text/html; charset=utf-8', ...corsHeaders() },
        });
      }
      if (c.free) {
        return json(
          200,
          {
            endpoint: `${url.origin}/v1/sponsor`,
            method: 'POST',
            paid: false,
            price_usd: 42,
            amount_atomic: quote.amount,
            note: 'free mode does not settle; not income',
          },
          {},
          true
        );
      }
      return paymentRequired402(quote, url.href, url.origin);
    }

    if (request.method === 'POST' && url.pathname === '/v1/sponsor') {
      const quote = sponsorCfg(c);
      if (c.free) {
        return json(200, { ok: true, mode: 'free', goalUsd: GOAL_USD, note: 'free mode does not settle; not income' }, {}, true);
      }
      const payHeader = request.headers.get('payment-signature') || request.headers.get('x-payment');
      if (!payHeader) return paymentRequired402(quote, url.href, url.origin);
      const payload = b64decode(payHeader);
      if (!payload) return paymentRequired402(quote, url.href, url.origin, 'malformed payment header');
      const ver = payload.x402Version === 2 ? 2 : 1;
      const reqs = ver === 2 ? paymentRequirementsV2(quote) : paymentRequirementsV1(quote, url.href);
      reqs.extensions = bazaarExtension(url.origin);
      const verifyBody = { x402Version: ver, paymentPayload: payload, paymentRequirements: reqs };
      const verify = await facilitatorCall(env, quote, 'verify', verifyBody);
      if (!verify.json || verify.json.isValid !== true) {
        return paymentRequired402(quote, url.href, url.origin, `payment verification failed: ${verify.json?.invalidReason || `facilitator ${verify.status}`}`);
      }
      const settle = await facilitatorCall(env, quote, 'settle', verifyBody);
      if (!settle.json || settle.json.success !== true) {
        return paymentRequired402(quote, url.href, url.origin, `settlement failed: ${settle.json?.errorReason || `facilitator ${settle.status}`}`);
      }
      const receipt = b64encode(settle.json);
      return json(200, { ok: true, goalUsd: GOAL_USD, note: '42 USDC settlement accepted; counted only if it is not a self-pay' }, { 'PAYMENT-RESPONSE': receipt, 'X-PAYMENT-RESPONSE': receipt });
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
      // The Bazaar declaration must ride on the requirements object the FACILITATOR sees,
      // not only on the 402 we show the buyer. Two code paths built those separately here,
      // and only the buyer-facing one carried `extensions.bazaar` — so CDP never received a
      // declaration and never indexed the resource. Same structural bug, independently
      // found and fixed by another operator in x402-foundation/x402#2112, who then proved a
      // real mainnet settlement succeeds with the field present on both verify and settle.
      reqs.extensions = bazaarExtension(url.origin);
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

export { check, validatePolicy, globMatch, DEFAULT_POLICY, assessReceived, readUsdcBalance, satsForGoal, SELF_TEST_USD, GOAL_USD };
