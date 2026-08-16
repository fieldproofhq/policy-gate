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

/** Cumulative exposure, mirroring the MIT engine in policy-engine.js.
 *
 *  A per-action gate cannot see repetition: 49 payments of $40 each pass a "$50 needs
 *  approval" rule individually, and every verdict is defensible. Determinism does not help —
 *  same input, same verdict is a promise about a function, and the question omitted history.
 *  `intended` counts alongside `committed` so a burst still in flight is not invisible to the
 *  control meant to bound it.
 */
function cumulativeValue(ledger, field) {
  if (!ledger || typeof ledger !== 'object') return undefined;
  if (ledger[`committed_${field}`] === undefined && ledger[`intended_${field}`] === undefined) {
    return undefined;
  }
  const committed = Number(ledger[`committed_${field}`] ?? 0);
  const intended = Number(ledger[`intended_${field}`] ?? 0);
  if (!Number.isFinite(committed) || !Number.isFinite(intended)) return undefined;
  return committed + intended;
}

function cumulativeMatches(cond, ledger) {
  const field = cond.field || 'usd';
  // An outstanding `unknown` means an effect was dispatched and never resolved. The system has
  // lost track of this quantity, which is when moving more is least defensible. Only observing
  // the target closes it — never a clock.
  const unknown = Number(ledger?.[`unknown_${field}`] ?? 0);
  if (Number.isFinite(unknown) && unknown > 0) return 'unknown-outstanding';
  const val = cumulativeValue(ledger, field);
  if (val === undefined) return 'unanswerable';
  if ('gt' in cond) return val > cond.gt;
  if ('gte' in cond) return val >= cond.gte;
  if ('lt' in cond) return val < cond.lt;
  if ('lte' in cond) return val <= cond.lte;
  if ('eq' in cond) return val === cond.eq;
  return false;
}

/** Returns true | false | 'unanswerable'. */
function ruleMatches(rule, req, ledger) {
  const m = rule.match || {};
  if (m.action && !globMatch(m.action, req.action)) return false;
  if (m.actor && !globMatch(m.actor, req.actor || '')) return false;
  if (Array.isArray(m.where)) {
    for (const cond of m.where) {
      if (!condMatches(cond, req.params)) return false;
    }
  }
  if (Array.isArray(m.cumulative)) {
    for (const cond of m.cumulative) {
      const hit = cumulativeMatches(cond, ledger);
      if (hit === 'unanswerable' || hit === 'unknown-outstanding') return hit;
      if (!hit) return false;
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

function check(policy, request, ledger) {
  const errors = validatePolicy(policy);
  if (errors.length) return { error: 'invalid_policy', details: errors };
  if (!request || typeof request.action !== 'string' || !request.action.length) {
    return { error: 'invalid_request', details: ['request.action (string) is required'] };
  }
  const rules = policy.rules || [];
  for (const rule of rules) {
    const hit = ruleMatches(rule, request, ledger);
    if (hit === 'unknown-outstanding') {
      return {
        decision: 'deny',
        matched_rule: rule.id || null,
        tier: rule.tier !== undefined ? Number(rule.tier) : null,
        tier_label: rule.tier !== undefined ? policy.tiers[String(rule.tier)].label || null : null,
        rationale:
          `Rule "${rule.id || 'unnamed'}" bounds cumulative exposure and the ledger reports an unresolved ` +
          'effect. The system has lost track of this quantity, which is when moving more is least defensible. ' +
          'Close it by observing the target, not by waiting.',
        policy_version: policy.version || null,
        default_applied: false,
        unresolved_intent: true,
      };
    }
    if (hit === 'unanswerable') {
      // Fail closed: the policy bounds cumulative exposure and the caller sent no ledger.
      // A cap you can skip by omitting state is decorative.
      return {
        decision: 'deny',
        matched_rule: rule.id || null,
        tier: rule.tier !== undefined ? Number(rule.tier) : null,
        tier_label: rule.tier !== undefined ? policy.tiers[String(rule.tier)].label || null : null,
        rationale:
          `Rule "${rule.id || 'unnamed'}" bounds cumulative exposure, and no ledger was supplied. ` +
          'Send ledger.committed_* and ledger.intended_* for the window, or the cap cannot be enforced.',
        policy_version: policy.version || null,
        default_applied: false,
        ledger_required: true,
      };
    }
    if (!hit) continue;
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
    { id: 'vault-list-names', match: { action: 'vault.opaque.list' }, tier: 0, rationale: 'Listing vault names is not a secret read.' },
    { id: 'domain-inventory', match: { action: 'domain.inventory' }, tier: 0, rationale: 'Read-only domain inventory is separate from DNS or website writes.' },
    { id: 'vault-opaque-write', match: { action: 'vault.opaque.write' }, tier: 1, rationale: 'Write a secret into KeePass or the OS store. The value never enters the mesh.' },
    { id: 'vault-opaque-use', match: { action: 'vault.opaque.use' }, tier: 1, rationale: 'Invoke a secret by opaque reference. The agent never sees the value.' },
    { id: 'connector-invoke', match: { action: 'connector.invoke' }, tier: 1, rationale: 'Approved connectors may be invoked. Fail closed on revoke, expiry, or missing scope.' },
    { id: 'dns-write', match: { action: 'dns.write' }, tier: 1, rationale: 'DNS writes need capability, scope, diff, and verification. Separate from website writes.' },
    { id: 'website-create', match: { action: 'website.create' }, tier: 1 },
    { id: 'website-update', match: { action: 'website.update' }, tier: 1 },
    { id: 'account-create-mesh', match: { action: 'account.create.mesh' }, tier: 1, rationale: 'Service accounts created for the mesh are for the mesh to operate.' },
    { id: 'no-secret-read', match: { action: 'vault.opaque.read' }, tier: 3, rationale: 'Secret values must never be retrieved into the mesh.' },
    { id: 'no-secret-expose', match: { action: 'secret.expose' }, tier: 3, rationale: 'Secret values must never appear in prompts, logs, files, or receipts.' },
    { id: 'no-browser-extract', match: { action: 'auth.browser.**' }, tier: 3, rationale: 'Browser password extraction remains prohibited.' },
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
    { id: 'no-credentials', match: { action: 'auth.**' }, tier: 3, rationale: 'Raw credential values stay out of the mesh. Opaque vault and connector use is a different action family.' },
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

/** The default policy bounds each payment and says nothing about the fiftieth.
 *
 *  Forty-nine payments of $40 each pass `small-payments-need-approval` individually, and every
 *  verdict is defensible — which is exactly what makes the log useless afterwards. This variant
 *  adds the cumulative bound, first in the list so it is reached before the per-action rule.
 *
 *  It is shipped as a SEPARATE built-in rather than folded into the default on purpose: it
 *  requires the caller to supply a ledger and denies when they do not, so adopting it is a
 *  decision to actually maintain that state. A cap nobody feeds is worse than no cap, because
 *  it looks like one in an audit.
 */
const CAPPED_POLICY = {
  ...DEFAULT_POLICY,
  version: DEFAULT_POLICY.version,
  name: 'default-action-tiers-capped',
  rules: [
    {
      id: 'cumulative-spend-cap',
      match: { action: 'payments.*', cumulative: [{ field: 'usd', gt: 50 }] },
      tier: 3,
      rationale:
        'Committed plus intended spend in the window is over $50. Individually-approved payments still aggregate, ' +
        'and the per-action rules below cannot see that.',
    },
    ...DEFAULT_POLICY.rules,
  ],
};

const BUILTINS = {
  'default-action-tiers': DEFAULT_POLICY,
  'default-action-tiers-capped': CAPPED_POLICY,
};

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
        policy_id: { type: 'string', description: 'Built-in policy id; see policy_rules. "default-action-tiers-capped" adds a cumulative spend bound.' },
        policy: { type: 'object', description: 'Your own policy document, evaluated instead of ours' },
        ledger: {
          type: 'object',
          description:
            'Optional cumulative exposure for the window. A per-action gate cannot see repetition: 49 payments of $40 each pass a $50 rule individually. Omit it and any policy declaring a cumulative bound returns deny with ledger_required — a cap you can skip by omitting state is decorative. Explicit zeros are an answer; an absent object is not.',
          properties: {
            committed_usd: { type: 'number', description: 'Spend already known to have happened in the window' },
            intended_usd: { type: 'number', description: 'Dispatched and not yet confirmed. Counts toward the bound, so a burst in flight is not invisible to it.' },
            unknown_usd: { type: 'number', description: 'Dispatched and never resolved. Any value above zero denies with unresolved_intent, regardless of headroom: the system has lost track of this quantity. It closes by observing the target, never by a clock.' },
          },
        },
      },
    },
  },
  {
    name: 'first_42_sponsor',
    description:
      'Pay Fieldproof $42. Returns every live rail: Stripe card_uri, EIP-681 usdc_uri, BIP-21 btc_uri, x402 POST /v1/sponsor, Zelle, and GET /v1/invoice. One settlement meets the first-$42 bar.',
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

const USDC_BASE = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';

function usdcEip681(payTo) {
  return `ethereum:${USDC_BASE}@8453/transfer?address=${payTo}&uint256=42000000`;
}

function formatBtcAmount(sats) {
  return (sats / 1e8).toFixed(8).replace(/0+$/, '').replace(/\.$/, '');
}

function btcBip21(sats) {
  return sats ? `bitcoin:${BTC_ADDRESS}?amount=${formatBtcAmount(sats)}` : `bitcoin:${BTC_ADDRESS}`;
}

function wantsUriList(request) {
  return /text\/uri-list/i.test(request.headers.get('accept') || '');
}

function wantsJson(request) {
  return /application\/json/i.test(request.headers.get('accept') || '');
}

const ZELLE_EMAIL = '3labsio@gmail.com';
const GUMROAD_PACK = 'https://store.3labs.io/l/agentic-ai-governance-pack?wanted=true';
const GUMROAD_TIP = 'https://store.3labs.io/l/tip-jar?wanted=true';

function zelleMailto() {
  return `mailto:${ZELLE_EMAIL}?subject=Fieldproof%20%2442&body=Send%20%2442.00%20via%20Zelle%20to%203labsio%40gmail.com%20memo%20Fieldproof.`;
}

function uriListResponse(uri) {
  return new Response(`${uri}\n`, {
    status: 200,
    headers: {
      'content-type': 'text/uri-list; charset=utf-8',
      Link: paymentLinkHeader(),
      ...corsHeaders(),
    },
  });
}

function fieldproofInvoice(origin, payTo, btc) {
  const usdcUri = usdcEip681(payTo);
  const btcUri = btcBip21(btc?.satsFor42 || null);
  return {
    id: 'fieldproof-42',
    amountUsd: GOAL_USD,
    currency: 'USD',
    description: 'One $42 payment meets the first-income bar. Self-test excluded.',
    card: STRIPE_PAYMENT_LINK,
    methods: [
      {
        scheme: 'stripe',
        url: STRIPE_PAYMENT_LINK,
        amountUsd: GOAL_USD,
        methods: ['card', 'cashapp', 'link', 'us_bank_account', 'klarna', 'afterpay_clearpay', 'affirm'],
      },
      {
        scheme: 'eip681',
        uri: usdcUri,
        network: 'eip155:8453',
        asset: 'USDC',
        amountUsd: GOAL_USD,
        amountAtomic: '42000000',
        payTo,
      },
      {
        scheme: 'bip21',
        uri: btcUri,
        asset: 'BTC',
        amountUsd: GOAL_USD,
        amountSats: btc?.satsFor42 ?? null,
        payTo: BTC_ADDRESS,
      },
      {
        scheme: 'x402',
        url: `${origin}/v1/sponsor`,
        method: 'POST',
        asset: 'USDC',
        amountUsd: GOAL_USD,
        amountAtomic: '42000000',
      },
      {
        scheme: 'zelle',
        payTo: ZELLE_EMAIL,
        uri: zelleMailto(),
        amountUsd: GOAL_USD,
        memo: 'Fieldproof',
      },
      {
        scheme: 'gumroad',
        url: GUMROAD_PACK,
        asset: 'USD',
        amountUsd: GOAL_USD,
        product: 'agentic-ai-governance-pack',
      },
      {
        scheme: 'gumroad-tip',
        url: GUMROAD_TIP,
        asset: 'USD',
        amountUsd: GOAL_USD,
        product: 'tip-jar',
      },
    ],
  };
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
function walletPayControls(payTo, payUri) {
  const to = String(payTo || '').toLowerCase();
  if (!/^0x[a-f0-9]{40}$/.test(to)) return '';
  const invoice = String(payUri || '');
  return `<p><button type="button" id="fp-wallet-pay" style="background:#111;color:#fff;border:0;padding:.7rem 1.1rem;border-radius:999px;font-weight:600;cursor:pointer">Pay 42 USDC in this browser</button>
<span id="fp-wallet-status" style="display:block;margin-top:.55rem;color:#444"></span></p>
<script>
(function(){
  var btn = document.getElementById("fp-wallet-pay");
  var status = document.getElementById("fp-wallet-status");
  var USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";
  var PAY_TO = "${to}";
  var PAY_URI = ${JSON.stringify(invoice)};
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
  if (window.ethereum) {
    btn.click();
  } else if (PAY_URI && /Mobi|Android|iPhone|iPad/i.test(navigator.userAgent)) {
    say("Opening your wallet…");
    location.replace(PAY_URI);
  } else {
    say("No browser wallet. Use the QR, the wallet link, or Pay $42 with card.");
  }
})();
</script>`;
}

function cardFallbackHtml() {
  return `<p>Prefer card? <a href="${STRIPE_PAYMENT_LINK}" target="_blank" rel="noopener noreferrer" style="display:inline-block;background:#111;color:#fff;text-decoration:none;padding:.55rem .95rem;border-radius:999px;font-weight:600">Pay $42 with card</a> — also Cash App, Link, or US bank debit.</p>`;
}

function sponsorHtml(origin, payTo) {
  const payUri = `ethereum:0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913@8453/transfer?address=${payTo}&uint256=42000000`;
  const qrUrl = `https://api.qrserver.com/v1/create-qr-code/?size=240x240&data=${encodeURIComponent(payUri)}`;
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Pay 42 USDC — Fieldproof</title>
<link rel="payment" href="${STRIPE_PAYMENT_LINK}">
</head><body style="font-family:system-ui,sans-serif;max-width:40rem;margin:2rem auto;padding:0 1rem;line-height:1.5;background:#f4efe6;color:#111">
<h1>Pay 42 USDC on Base</h1>
<p>One transfer of <strong>42 USDC</strong> on <strong>Base</strong>. Agents can settle the same amount via x402 <code>POST /v1/sponsor</code>. This page does not open card checkout.</p>
${walletPayControls(payTo, payUri)}
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
const STRIPE_CFO_LINK = 'https://buy.stripe.com/6oU28sa5Y9bLgTn9Lf1sQ01';
const STRIPE_COO_LINK = 'https://buy.stripe.com/4gM7sM4LEafPcD72iN1sQ02';
const STRIPE_CTO_LINK = 'https://buy.stripe.com/6oU5kE91UbjTeLfg9D1sQ03';
const STRIPE_CISO_LINK = 'https://buy.stripe.com/7sY14odia87H32xe1v1sQ04';
const STRIPE_ETHICS_LINK = 'https://buy.stripe.com/aFa9AUce6afPdHb0aF1sQ05';
const CFO_ZIP = 'https://fieldproofhq.github.io/csuite/cfo/Fractional-CFO-Launch-Kit.zip';
const COO_ZIP = 'https://fieldproofhq.github.io/csuite/coo/Fractional-COO-Launch-Kit.zip';
const CTO_ZIP = 'https://fieldproofhq.github.io/csuite/cto/Fractional-CTO-Launch-Kit.zip';
const CISO_ZIP = 'https://fieldproofhq.github.io/csuite/ciso/Fractional-CISO-Launch-Kit.zip';
const ETHICS_ZIP = 'https://fieldproofhq.github.io/ethics/Fieldproof-Ethics-Check-Launch-Kit.zip';

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

function stripeQrUrl() {
  return `https://api.qrserver.com/v1/create-qr-code/?size=240x240&data=${encodeURIComponent(STRIPE_PAYMENT_LINK)}`;
}

function usdcQrUrl(payTo) {
  return `https://api.qrserver.com/v1/create-qr-code/?size=240x240&data=${encodeURIComponent(usdcEip681(payTo))}`;
}

function btcQrUrl(sats = null) {
  return `https://api.qrserver.com/v1/create-qr-code/?size=240x240&data=${encodeURIComponent(btcBip21(sats))}`;
}

function zelleQrUrl() {
  return `https://api.qrserver.com/v1/create-qr-code/?size=240x240&data=${encodeURIComponent(zelleMailto())}`;
}

function npmFunding() {
  return [
    { type: 'individual', url: 'https://fieldproofhq.github.io/offer/' },
    { type: 'stripe', url: STRIPE_PAYMENT_LINK },
  ];
}

function webfingerJrd(origin, resource) {
  const host = new URL(origin).host;
  return {
    subject: resource || `acct:pay@${host}`,
    aliases: ['https://fieldproofhq.github.io/offer/', `${origin}/v1/invoice`],
    properties: {
      'http://schema.org/price': '42.00',
      'http://schema.org/priceCurrency': 'USD',
    },
    links: [
      { rel: 'payment', href: STRIPE_PAYMENT_LINK, type: 'text/html' },
      { rel: 'http://webfinger.net/rel/profile-page', href: 'https://fieldproofhq.github.io/' },
      { rel: 'https://fieldproofhq.github.io/rel/invoice', href: `${origin}/v1/invoice`, type: 'application/json' },
      { rel: 'https://fieldproofhq.github.io/rel/card-uri', href: `${origin}/v1/pay/card.uri`, type: 'text/uri-list' },
      { rel: 'https://fieldproofhq.github.io/rel/usdc-uri', href: `${origin}/v1/pay/usdc.uri`, type: 'text/uri-list' },
      { rel: 'https://fieldproofhq.github.io/rel/btc-uri', href: `${origin}/v1/pay/btc.uri`, type: 'text/uri-list' },
      { rel: 'https://fieldproofhq.github.io/rel/zelle-uri', href: `${origin}/v1/pay/zelle.uri`, type: 'text/uri-list' },
    ],
  };
}

function webfingerKnown(origin, resource) {
  const host = new URL(origin).host;
  const known = new Set([
    `acct:pay@${host}`,
    'acct:3labsio@gmail.com',
    origin,
    `${origin}/`,
    `${origin}/v1/invoice`,
    'https://fieldproofhq.github.io',
    'https://fieldproofhq.github.io/',
    'https://fieldproofhq.github.io/offer/',
    'https://store.3labs.io',
    'https://store.3labs.io/',
  ]);
  return known.has(resource);
}

function hostMetaJson(origin) {
  return {
    subject: origin,
    properties: {
      'http://schema.org/price': '42.00',
      'http://schema.org/priceCurrency': 'USD',
    },
    links: [
      {
        rel: 'lrdd',
        type: 'application/jrd+json',
        template: `${origin}/.well-known/webfinger?resource={uri}`,
      },
      { rel: 'payment', href: STRIPE_PAYMENT_LINK, type: 'text/html' },
      { rel: 'describedby', href: `${origin}/v1/invoice`, type: 'application/json' },
      { rel: 'https://fieldproofhq.github.io/rel/card-uri', href: `${origin}/v1/pay/card.uri`, type: 'text/uri-list' },
      { rel: 'https://fieldproofhq.github.io/rel/usdc-uri', href: `${origin}/v1/pay/usdc.uri`, type: 'text/uri-list' },
      { rel: 'https://fieldproofhq.github.io/rel/btc-uri', href: `${origin}/v1/pay/btc.uri`, type: 'text/uri-list' },
    ],
  };
}

function didWeb(origin) {
  const host = new URL(origin).host;
  const id = `did:web:${host}`;
  const alsoKnownAs = ['https://fieldproofhq.github.io/', `acct:pay@${host}`];
  if (host !== 'fieldproofhq.github.io') alsoKnownAs.push('did:web:fieldproofhq.github.io');
  if (host !== 'policy-gate.3labsio.workers.dev') alsoKnownAs.push('did:web:policy-gate.3labsio.workers.dev');
  return {
    '@context': ['https://www.w3.org/ns/did/v1'],
    id,
    alsoKnownAs,
    service: [
      { id: `${id}#stripe`, type: 'PaymentService', serviceEndpoint: STRIPE_PAYMENT_LINK },
      { id: `${id}#invoice`, type: 'PaymentService', serviceEndpoint: `${origin}/v1/invoice` },
      { id: `${id}#offer`, type: 'PaymentService', serviceEndpoint: `${origin}/v1/offer` },
      { id: `${id}#card`, type: 'PaymentService', serviceEndpoint: `${origin}/v1/pay/card.uri` },
      { id: `${id}#usdc`, type: 'PaymentService', serviceEndpoint: `${origin}/v1/pay/usdc.uri` },
      { id: `${id}#btc`, type: 'PaymentService', serviceEndpoint: `${origin}/v1/pay/btc.uri` },
    ],
  };
}

function hostMetaXml(origin) {
  return [
    '<?xml version="1.0" encoding="UTF-8"?>',
    '<XRD xmlns="http://docs.oasis-open.org/ns/xri/xrd-1.0">',
    `  <Link rel="lrdd" type="application/jrd+json" template="${origin}/.well-known/webfinger?resource={uri}"/>`,
    `  <Link rel="payment" href="${STRIPE_PAYMENT_LINK}"/>`,
    '</XRD>',
    '',
  ].join('\n');
}

function humansTxt(origin) {
  return [
    '/* TEAM */',
    'Operator: Fieldproof',
    'Contact: 3labsio@gmail.com',
    'Site: https://fieldproofhq.github.io/',
    'Pay: ' + STRIPE_PAYMENT_LINK,
    '',
    '/* SITE */',
    'Invoice: ' + origin + '/v1/invoice',
    'Card: ' + origin + '/v1/pay/card.uri',
    'USDC: ' + origin + '/v1/pay/usdc.uri',
    'BTC: ' + origin + '/v1/pay/btc.uri',
    'Zelle: ' + origin + '/v1/pay/zelle.uri',
    'Pack: ' + origin + '/v1/pay/pack.uri',
    'Tip: ' + origin + '/v1/pay/tip-jar.uri',
    'Skill: ' + origin + '/skills/pay/SKILL.md',
    'MCP: ' + origin + '/mcp',
    'Standards: https://humanstxt.org/',
    '',
  ].join('\n');
}

function nodeInfoIndex(origin) {
  return {
    links: [
      {
        rel: 'http://nodeinfo.diaspora.software/ns/schema/2.1',
        href: `${origin}/nodeinfo/2.1`,
      },
    ],
  };
}

function nodeInfo21(origin) {
  return {
    version: '2.1',
    software: {
      name: 'fieldproof-policy-gate',
      version: '0.2',
      repository: 'https://github.com/fieldproofhq/policy-gate',
      homepage: 'https://fieldproofhq.github.io/',
    },
    protocols: ['x402'],
    services: { inbound: [], outbound: [] },
    openRegistrations: false,
    usage: { users: { total: 0 }, localPosts: 0 },
    metadata: {
      nodeName: 'Fieldproof',
      nodeDescription: 'Pay $42 with card or 42 USDC on Base.',
      payment: STRIPE_PAYMENT_LINK,
      invoice: `${origin}/v1/invoice`,
      card_uri: `${origin}/v1/pay/card.uri`,
      usdc_uri: `${origin}/v1/pay/usdc.uri`,
      btc_uri: `${origin}/v1/pay/btc.uri`,
      zelle_uri: `${origin}/v1/pay/zelle.uri`,
    },
  };
}

function securityTxt(origin) {
  return [
    'Contact: mailto:3labsio@gmail.com',
    `Contact: ${origin}/v1/invoice`,
    `Expires: 2027-08-16T00:00:00.000Z`,
    'Preferred-Languages: en',
    `Canonical: ${origin}/.well-known/security.txt`,
    `Policy: ${origin}/skills/pay/SKILL.md`,
    `Hiring: https://fieldproofhq.github.io/offer/`,
    `# Pay $42: ${STRIPE_PAYMENT_LINK}`,
    `# Card URI: ${origin}/v1/pay/card.uri`,
    `# Zelle $42: ${origin}/v1/pay/zelle.uri`,
    '',
  ].join('\n');
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
      '/.well-known/nodeinfo': {
        get: {
          operationId: 'nodeInfoIndex',
          summary: 'NodeInfo index. Follow the 2.1 link for payment metadata.',
          responses: { 200: { description: 'NodeInfo well-known index' } },
        },
      },
      '/nodeinfo/2.1': {
        get: {
          operationId: 'nodeInfo21',
          summary: 'NodeInfo 2.1 document. metadata.payment is the live $42 Stripe checkout.',
          responses: { 200: { description: 'NodeInfo 2.1 with payment metadata' } },
        },
      },
      '/.well-known/host-meta.json': {
        get: {
          operationId: 'hostMetaJson',
          summary: 'RFC 6415 JSON host-meta. rel=payment is the live $42 Stripe checkout.',
          responses: { 200: { description: 'application/jrd+json host-meta' } },
        },
      },
      '/.well-known/did.json': {
        get: {
          operationId: 'didWeb',
          summary: 'W3C did:web document. PaymentService #stripe is the live $42 Stripe checkout.',
          responses: { 200: { description: 'application/did+json DID document' } },
        },
      },
      '/.well-known/webfinger': {
        get: {
          operationId: 'webfinger',
          summary: 'RFC 7033 WebFinger. Query resource=acct:pay@{host} or acct:3labsio@gmail.com for $42 payment links.',
          responses: {
            200: { description: 'application/jrd+json with rel=payment' },
            400: { description: 'resource query is required' },
          },
        },
      },
      '/humans.txt': {
        get: {
          operationId: 'humansTxt',
          summary: 'humans.txt listing the operator and every live $42 rail',
          responses: { 200: { description: 'text/plain humans.txt with live $42 rails' } },
        },
      },
      '/.well-known/security.txt': {
        get: {
          operationId: 'securityTxt',
          summary: 'RFC 9116 security.txt. Contact is the $42 Zelle inbox and the live invoice.',
          responses: { 200: { description: 'text/plain security.txt with live $42 rails' } },
        },
      },
      '/package.json': {
        get: {
          operationId: 'npmFunding',
          summary: 'npm-style funding document. Browsers get a live $42 checkout; agents get package.json with funding URLs.',
          responses: { 200: { description: 'HTML checkout when Accept includes text/html; otherwise package.json with funding URLs.' } },
        },
      },
      '/pay': {
        get: {
          operationId: 'payCardRedirect',
          summary: 'Browser short URL: live $42 HTML checkout that auto-opens Stripe. Non-HTML GET still 302s to the Payment Link.',
          responses: {
            200: { description: 'HTML checkout that auto-opens Stripe when Accept includes text/html.' },
            302: { description: `Redirect to ${STRIPE_PAYMENT_LINK}` },
          },
        },
      },
      '/v1/quote': {
        get: {
          operationId: 'quote42',
          summary: 'Alias of /v1/offer for directories that key on URL. Browsers get a live Stripe checkout; otherwise HTTP 402 with 42 USDC plus card fallback.',
          responses: {
            200: { description: 'HTML checkout that auto-opens Stripe when Accept includes text/html.' },
            402: { description: 'Payment required. accepts is USDC; fallback.url is the $42 card path.' },
          },
        },
        post: {
          operationId: 'quote42Post',
          summary: 'POST-only $42 quote. Always 402 with 42 USDC plus card fallback.',
          responses: {
            402: { description: 'Payment required. accepts is USDC; fallback.url is the $42 card path.' },
          },
        },
      },
      '/v1/offer': {
        get: {
          operationId: 'offer42',
          summary: 'Canonical $42 quote. Browsers get a live Stripe checkout; otherwise HTTP 402 with 42 USDC plus card fallback.',
          responses: {
            200: { description: 'HTML checkout that auto-opens Stripe when Accept includes text/html.' },
            402: { description: 'Payment required. accepts is USDC; fallback.url is the $42 card path.' },
          },
        },
        post: {
          operationId: 'offer42Post',
          summary: 'Same $42 quote for POST-only agents. Always 402 with 42 USDC plus card fallback.',
          responses: {
            402: { description: 'Payment required. accepts is USDC; fallback.url is the $42 card path.' },
          },
        },
      },
      '/v1/invoice': {
        get: {
          operationId: 'invoice42',
          summary: 'HTTP 200 multi-rail $42 invoice. Browsers get an HTML checkout that auto-opens Stripe; agents get JSON or text/uri-list.',
          responses: { 200: { description: 'HTML checkout (Accept: text/html), JSON invoice, or text/uri-list of live rails.' } },
        },
      },
      '/skills/pay/SKILL.md': {
        get: {
          operationId: 'paySkill',
          summary: 'Agent skill: how to pay Fieldproof $42 on every live rail. Browsers get a live checkout; agents get markdown.',
          responses: { 200: { description: 'HTML checkout when Accept includes text/html; otherwise text/markdown skill with live checkout URLs.' } },
        },
      },
      '/v1/pay/card.png': {
        get: {
          operationId: 'payCardQr',
          summary: '302 to a scannable QR of the live $42 Stripe Payment Link',
          responses: { 302: { description: 'Redirect to QR image of the Stripe checkout' } },
        },
      },
      '/v1/pay/card.uri': {
        get: {
          operationId: 'payCardUri',
          summary: 'text/uri-list of the live $42 Stripe Payment Link. Agents open the first URI.',
          responses: { 200: { description: 'text/uri-list; one https://buy.stripe.com/… URI' } },
        },
      },
      '/v1/pay/usdc.png': {
        get: {
          operationId: 'payUsdcQr',
          summary: '302 to a scannable QR of the 42 USDC EIP-681 invoice on Base',
          responses: { 302: { description: 'Redirect to QR image of the 42 USDC transfer' } },
        },
      },
      '/v1/pay/usdc.uri': {
        get: {
          operationId: 'payUsdcUri',
          summary: 'text/uri-list EIP-681 invoice for 42 USDC on Base. Open in any wallet that understands ethereum: URIs.',
          responses: { 200: { description: 'text/uri-list; one ethereum: transfer URI' } },
        },
      },
      '/v1/pay/tip-jar.uri': {
        get: {
          operationId: 'payTipUri',
          summary: 'text/uri-list of the live $42 Gumroad tip-jar checkout',
          responses: { 200: { description: 'text/uri-list; one store.3labs.io tip-jar URI' } },
        },
      },
      '/v1/pay/pack.uri': {
        get: {
          operationId: 'payPackUri',
          summary: 'text/uri-list of the live $42 Gumroad Governance Pack checkout',
          responses: { 200: { description: 'text/uri-list; one store.3labs.io pack URI' } },
        },
      },
      '/v1/pay/zelle.uri': {
        get: {
          operationId: 'payZelleUri',
          summary: 'text/uri-list mailto invoice for $42 via Zelle to 3labsio@gmail.com',
          responses: { 200: { description: 'text/uri-list; one mailto: URI' } },
        },
      },
      '/v1/pay/zelle.png': {
        get: {
          operationId: 'payZelleQr',
          summary: '302 to a scannable QR of the $42 Zelle mailto invoice',
          responses: { 302: { description: 'Redirect to QR image of the Zelle mailto' } },
        },
      },
      '/v1/pay/btc.uri': {
        get: {
          operationId: 'payBtcUri',
          summary: 'text/uri-list BIP-21 invoice for ~$42 BTC at the live spot quote.',
          responses: { 200: { description: 'text/uri-list; one bitcoin: URI with amount' } },
        },
      },
      '/v1/pay/scan': {
        get: {
          operationId: 'payScan',
          summary: 'QR board for 42 USDC, BIP21 Bitcoin, and $42 Zelle. Does not auto-open card checkout.',
          responses: { 200: { description: 'HTML scan board' } },
        },
      },
      '/v1/pay/btc.png': {
        get: {
          operationId: 'payBtcQr',
          summary: '302 to a scannable QR of the live BIP-21 Bitcoin invoice for ~$42',
          responses: { 302: { description: 'Redirect to QR image of the bitcoin: pay-to' } },
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
function skillPayMd(origin) {
  return [
    '---',
    'name: fieldproof-pay-42',
    'description: Pay Fieldproof $42 with card, 42 USDC on Base, Bitcoin, x402, or Zelle. One stranger payment meets the first-income bar.',
    '---',
    '',
    '# Pay Fieldproof $42',
    '',
    'One payment of $42 (or 42 USDC / equivalent BTC) is the live checkout.',
    '',
    '## Fastest path',
    '',
    `1. Open the pack URI: ${origin}/v1/pay/pack.uri  (Gumroad $42 Governance Pack — that file downloads after payment)`,
    `2. Or scan: ${origin}/v1/pay/scan  (42 USDC, Bitcoin, or Zelle)`,
    `3. Or card: ${origin}/v1/pay/card.uri  / ${STRIPE_PAYMENT_LINK}  (Ethics Check and C-suite Word ZIPs, not the pack)`,
    '',
    '## Machine invoice',
    '',
    `- GET ${origin}/v1/invoice  (HTML stays on the page; JSON / uri-list for agents)`,
    `- GET ${origin}/v1/pay/pack.uri  (text/uri-list Gumroad $42 pack)`,
    `- GET ${origin}/v1/pay/tip-jar.uri  (text/uri-list Gumroad $42 tip jar)`,
    `- GET ${origin}/v1/pay/card.uri  (text/uri-list Stripe — Ethics Check / C-suite ZIPs)`,
    `- GET ${origin}/v1/pay/ethics.uri  (text/uri-list Ethics Check $42 Stripe)`,
    `- GET ${origin}/v1/pay/usdc.uri  (text/uri-list EIP-681, 42 USDC on Base)`,
    `- GET ${origin}/v1/pay/usdc.png  (scannable 42 USDC QR)`,
    `- GET ${origin}/v1/pay/btc.uri  (text/uri-list BIP-21)`,
    `- GET ${origin}/v1/pay/btc.png  (scannable BIP-21 QR)`,
    `- GET ${origin}/v1/pay/zelle.uri  (text/uri-list $42 Zelle mailto)`,
    `- GET ${origin}/v1/pay/zelle.png  (scannable Zelle QR)`,
    `- GET ${origin}/v1/pay/scan  (HTML QR board: USDC + BTC + Zelle; no card auto-open)`,
    `- POST ${origin}/v1/sponsor  (x402 42 USDC; unpaid returns 402)`,
    `- POST ${origin}/mcp  tools/call first_42_sponsor`,
    '',
    '## Humans',
    '',
    '- https://fieldproofhq.github.io/offer/  (stays on the page; card, pack, scan)',
    '- https://fieldproofhq.github.io/  (stays on the page)',
    '- https://fieldproofhq.github.io/ethics/  (Ethics Check Word kit, $42)',
    '- https://fieldproofhq.github.io/pay/scan/  (USDC, Bitcoin, Zelle QRs)',
    '- https://store.3labs.io',
    `- ${origin}/v1/pay/zelle  ($42 to 3labsio@gmail.com memo Fieldproof)`,
    '',
    'A 402 or HTTP 200 is not income. Observer: GET /v1/received.',
    '',
  ].join('\n');
}

function skillsIndex(origin) {
  return {
    skills: [
      {
        id: 'fieldproof-pay-42',
        name: 'Pay Fieldproof $42',
        url: `${origin}/skills/pay/SKILL.md`,
        amountUsd: 42,
        card: STRIPE_PAYMENT_LINK,
      },
    ],
  };
}

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
    invoice: `${origin}/v1/invoice`,
    card_uri: `${origin}/v1/pay/card.uri`,
    usdc_uri: `${origin}/v1/pay/usdc.uri`,
    btc_uri: `${origin}/v1/pay/btc.uri`,
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
          'One $42 payment that meets the first-$42 bar. GET /v1/invoice for every live rail, open fallback.url for card, or POST /v1/sponsor for 42 USDC on Base.',
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

const defaultFetch = fetch;
let btcCache = null;

async function fetchJson(fetchImpl, url, timeoutMs = 2500) {
  const signal = typeof AbortSignal !== 'undefined' && typeof AbortSignal.timeout === 'function'
    ? AbortSignal.timeout(timeoutMs)
    : undefined;
  const res = await fetchImpl(url, signal ? { signal } : {});
  if (!res || res.ok === false) throw new Error(`http ${res?.status || 'fetch_failed'}`);
  return res.json();
}

async function observeBtc(fetchImpl = fetch) {
  const useCache = fetchImpl === defaultFetch;
  if (useCache && btcCache && Date.now() - btcCache.at < 30000) return btcCache.value;
  const addressSources = [
    `https://mempool.space/api/address/${BTC_ADDRESS}`,
    `https://blockstream.info/api/address/${BTC_ADDRESS}`,
  ];
  const priceReaders = [
    { url: 'https://mempool.space/api/v1/prices', pick: (json) => Number(json.USD) },
    { url: 'https://api.coinbase.com/v2/prices/BTC-USD/spot', pick: (json) => Number(json.data?.amount) },
    { url: 'https://api.kraken.com/0/public/Ticker?pair=XBTUSD', pick: (json) => Number(json.result?.XXBTZUSD?.c?.[0]) },
  ];
  let info = null;
  for (const url of addressSources) {
    try {
      const body = await fetchJson(fetchImpl, url);
      if (body && body.chain_stats) {
        info = body;
        break;
      }
    } catch {
      /* next Esplora */
    }
  }
  if (!info) throw new Error('btc address observe failed');
  let priceUsd = null;
  for (const reader of priceReaders) {
    try {
      const json = await fetchJson(fetchImpl, reader.url);
      const price = reader.pick(json);
      if (Number.isFinite(price) && price > 0) {
        priceUsd = price;
        break;
      }
    } catch {
      /* next public spot */
    }
  }
  const sats =
    Number(info.chain_stats?.funded_txo_sum || 0) -
    Number(info.chain_stats?.spent_txo_sum || 0) +
    Number(info.mempool_stats?.funded_txo_sum || 0);
  const revenueUsd = Number.isFinite(sats) && Number.isFinite(priceUsd)
    ? Number(((sats / 1e8) * priceUsd).toFixed(6))
    : (sats === 0 ? 0 : null);
  const observed = {
    address: BTC_ADDRESS,
    sats: Number.isFinite(sats) ? sats : null,
    priceUsd: Number.isFinite(priceUsd) ? priceUsd : null,
    revenueUsd,
    satsFor42: satsForGoal(priceUsd),
  };
  if (useCache) btcCache = { at: Date.now(), value: observed };
  return observed;
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
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Pay Fieldproof $42</title>
<link rel="payment" href="${STRIPE_PAYMENT_LINK}"></head><body style="font-family:system-ui,sans-serif;max-width:44rem;margin:2rem auto;padding:0 1rem;line-height:1.5;background:#f4efe6;color:#111">
<h1>Pay Fieldproof $42</h1>
<p>Every rail below is live. This page stays here so you can pick one. Fieldproof is a fractional C-suite for agentic teams. One payment. No Fieldproof account.</p>
<p><a href="${STRIPE_PAYMENT_LINK}" style="display:inline-block;background:#111;color:#fff;text-decoration:none;padding:.7rem 1.1rem;border-radius:999px;font-weight:600">Pay $42 with card</a></p>
<p>Card, Cash App, Link, US bank debit, Klarna, Afterpay, or Affirm. Card checkout delivers the Ethics Check and C-suite Word ZIPs, not the Governance Pack.</p>
<p>Other ways:</p>
<ul>
<li><a href="${origin}/v1/pay/card">Card checkout page</a> — opens the same $42 Stripe link</li>
<li><a href="https://store.3labs.io">Browse the store</a> — pack, CMO, tip jar, and live C-suite Word kits</li>
<li><a href="${origin}/v1/pay/pack">$42 Governance Pack</a> — seven templates, Gumroad card</li>
<li><a href="${origin}/v1/pay/cmo">$39 Fractional CMO kit</a> — humans and agents</li>
<li><a href="${origin}/v1/pay/cfo">$42 Fractional CFO kit</a> — six Word templates + ZIP</li>
<li><a href="${origin}/v1/pay/coo">$42 Fractional COO kit</a> — six Word templates + ZIP</li>
<li><a href="${origin}/v1/pay/cto">$42 Fractional CTO kit</a> — six Word templates + ZIP</li>
<li><a href="${origin}/v1/pay/ciso">$42 Fractional CISO kit</a> — six Word templates + ZIP</li>
<li><a href="${origin}/v1/pay/ethics">$42 Ethics Check kit</a> — six Word templates + ZIP</li>
<li><a href="${origin}/v1/pay/tip-jar">$42 tip jar</a> — listed at $42</li>
<li><a href="https://fieldproofhq.github.io/csuite/">Virtual C-suite</a> — C-suite Word kits live (CMO, CFO, COO, CTO, CISO)</li>
</ul>
<p>Or pay another way:</p>
<ul>
<li><a href="${origin}/v1/pay/scan">Scan USDC, Bitcoin, or Zelle</a> — QR board, no card redirect</li>
<li><a href="${origin}/v1/sponsor">42 USDC / x402</a> — in-browser wallet, QR, or agent POST /v1/sponsor</li>
<li><a href="${origin}/v1/pay/usdc">42 USDC on Base</a> — in-browser wallet, EIP-681, QR</li>
<li><a href="${origin}/v1/pay/zelle">$42 Zelle</a> — 3labsio@gmail.com</li>
<li><a href="${origin}/v1/pay/btc">${btcLabel}</a> — BIP21 Bitcoin</li>
<li><a href="${origin}/v1/pay/x402">x402 agent docs</a> — per-check quote</li>
</ul>
<p>More: <a href="https://fieldproofhq.github.io">fieldproofhq.github.io</a>.</p>
</body></html>`;
}

function scanPaysHtml(origin, btc = null) {
  const payTo = '0x07C2383008a9ed30581f27Db5531E19411c94fb3';
  const sats = btc?.satsFor42 || null;
  const usdcUri = usdcEip681(payTo);
  const btcUri = btcBip21(sats);
  const zelleUri = zelleMailto();
  const btcLabel = sats ? `${sats} sats (~$${GOAL_USD})` : '~$42 of BTC';
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Scan $42 — USDC, Bitcoin, Zelle</title>
<link rel="payment" href="${STRIPE_PAYMENT_LINK}">
</head><body style="font-family:system-ui,sans-serif;max-width:52rem;margin:2rem auto;padding:0 1rem;line-height:1.5;background:#f4efe6;color:#111">
<h1>Scan $42</h1>
<p>Three stranger-payable rails. This page does not open card checkout. One $42 receipt on any rail meets the bar.</p>
<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(14rem,1fr));gap:1rem">
<figure style="margin:0;background:#fff;border:1px solid #e6e1d8;border-radius:16px;padding:1rem;text-align:center">
<a href="${usdcUri}"><img src="${usdcQrUrl(payTo)}" width="240" height="240" alt="QR for 42 USDC on Base"></a>
<figcaption><a href="${origin}/v1/pay/usdc">42 USDC on Base</a></figcaption>
</figure>
<figure style="margin:0;background:#fff;border:1px solid #e6e1d8;border-radius:16px;padding:1rem;text-align:center">
<a href="${btcUri}"><img src="${btcQrUrl(sats)}" width="240" height="240" alt="QR for Bitcoin BIP21"></a>
<figcaption><a href="${origin}/v1/pay/btc">${btcLabel}</a><br><span style="word-break:break-all;font-size:.8rem">${BTC_ADDRESS}</span></figcaption>
</figure>
<figure style="margin:0;background:#fff;border:1px solid #e6e1d8;border-radius:16px;padding:1rem;text-align:center">
<a href="${zelleUri}"><img src="${zelleQrUrl()}" width="240" height="240" alt="QR for $42 Zelle"></a>
<figcaption><a href="${origin}/v1/pay/zelle">$42 Zelle</a> · 3labsio@gmail.com</figcaption>
</figure>
</div>
<p>Prefer card? <a href="${STRIPE_PAYMENT_LINK}">Pay $42 with card</a> · store: <a href="https://store.3labs.io">store.3labs.io</a></p>
</body></html>`;
}

function invoiceHtml(origin, payTo, btc = null) {
  const usdcUri = usdcEip681(payTo);
  const sats = btc?.satsFor42 || null;
  const btcUri = btcBip21(sats);
  const btcLabel = sats ? `${sats} sats (~$${GOAL_USD})` : `~$42 of BTC`;
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Pay $42 — Fieldproof invoice</title>
<link rel="payment" href="${STRIPE_PAYMENT_LINK}">
</head><body style="font-family:system-ui,sans-serif;max-width:44rem;margin:2rem auto;padding:0 1rem;line-height:1.5;background:#f4efe6;color:#111">
<h1>Pay $42</h1>
<p>This invoice is $42. This page stays here so you can pick a rail. One payment meets the first-income bar.</p>
<p><a href="${STRIPE_PAYMENT_LINK}" style="display:inline-block;background:#111;color:#fff;text-decoration:none;padding:.7rem 1.1rem;border-radius:999px;font-weight:600">Pay $42 with card</a></p>
${walletPayControls(payTo, usdcUri)}
<p>Other rails on this invoice:</p>
<ul>
<li><a href="${STRIPE_PAYMENT_LINK}">Card / Cash App / Link / bank / Klarna / Afterpay / Affirm</a></li>
<li><a href="${usdcUri}">42 USDC on Base (EIP-681)</a></li>
<li><a href="${btcUri}">${btcLabel} (BIP-21)</a></li>
<li><a href="${zelleMailto()}">$42 Zelle to ${ZELLE_EMAIL}</a></li>
<li><a href="${GUMROAD_PACK}">$42 Governance Pack</a></li>
<li><a href="${GUMROAD_TIP}">$42 tip jar</a></li>
<li><a href="${origin}/v1/sponsor">42 USDC x402 POST /v1/sponsor</a></li>
</ul>
<p>JSON: <a href="/v1/invoice">GET /v1/invoice</a> without HTML Accept. Agents: Accept text/uri-list. Scan: <a href="${origin}/v1/pay/scan">USDC / BTC / Zelle</a>.</p>
</body></html>`;
}

async function htmlCheckoutResponse(origin) {
  let btc = null;
  try { btc = await observeBtc(); } catch { btc = null; }
  return new Response(payIndexHtml(origin, btc), {
    status: 200,
    headers: { 'content-type': 'text/html; charset=utf-8', Link: paymentLinkHeader(), ...corsHeaders() },
  });
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
      id: 'scan-board',
      url: `${origin}/v1/pay/scan`,
      asset: 'USD',
      amount_usd: 42,
      meets_first_42: true,
      note: 'QR board for 42 USDC, BIP21 Bitcoin, and $42 Zelle; no card auto-open; one stranger payment on any rail meets the bar',
    },
    {
      id: 'stripe-payment-link',
      url: STRIPE_PAYMENT_LINK,
      asset: 'USD',
      amount_usd: 42,
      meets_first_42: true,
      note: 'live Stripe Payment Link; card, Cash App, Link, US bank, Klarna, Afterpay, Affirm; issues a Stripe invoice; optional company name and tax ID; after payment the confirmation lists the live C-suite Word ZIP downloads',
    },
    {
      id: 'card-uri',
      url: `${origin}/v1/pay/card.uri`,
      asset: 'USD',
      amount_usd: 42,
      pay_uri: STRIPE_PAYMENT_LINK,
      meets_first_42: true,
      note: 'text/uri-list of the live Stripe Payment Link; agents open the first URI',
    },
    {
      id: 'card-qr',
      url: `${origin}/v1/pay/card.png`,
      asset: 'USD',
      amount_usd: 42,
      pay_uri: STRIPE_PAYMENT_LINK,
      qr_url: stripeQrUrl(),
      meets_first_42: true,
      note: '302 to a scannable QR of the live $42 Stripe Payment Link',
    },
    {
      id: 'governance-pack',
      url: `${origin}/v1/pay/pack`,
      asset: 'USD',
      amount_usd: 42,
      pay_uri: STRIPE_PAYMENT_LINK,
      meets_first_42: true,
      note: 'HTML pay landing auto-opens the live $42 Stripe checkout; Gumroad overlay stays secondary',
    },
    {
      id: 'pack-uri',
      url: `${origin}/v1/pay/pack.uri`,
      asset: 'USD',
      amount_usd: 42,
      pay_uri: GUMROAD_PACK,
      meets_first_42: true,
      note: 'text/uri-list of the live $42 Governance Pack on Gumroad; that checkout delivers this pack, not a different kit',
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
      id: 'cfo-kit',
      url: `${origin}/v1/pay/cfo`,
      asset: 'USD',
      amount_usd: 42,
      pay_uri: STRIPE_CFO_LINK,
      meets_first_42: true,
      note: 'live Fractional CFO Launch Kit Word ZIP; one $42 Stripe payment meets the bar',
    },
    {
      id: 'coo-kit',
      url: `${origin}/v1/pay/coo`,
      asset: 'USD',
      amount_usd: 42,
      pay_uri: STRIPE_COO_LINK,
      meets_first_42: true,
      note: 'live Fractional COO Launch Kit Word ZIP; one $42 Stripe payment meets the bar',
    },
    {
      id: 'cto-kit',
      url: `${origin}/v1/pay/cto`,
      asset: 'USD',
      amount_usd: 42,
      pay_uri: STRIPE_CTO_LINK,
      meets_first_42: true,
      note: 'live Fractional CTO Launch Kit Word ZIP; one $42 Stripe payment meets the bar',
    },
    {
      id: 'ciso-kit',
      url: `${origin}/v1/pay/ciso`,
      asset: 'USD',
      amount_usd: 42,
      pay_uri: STRIPE_CISO_LINK,
      meets_first_42: true,
      note: 'live Fractional CISO Launch Kit Word ZIP; one $42 Stripe payment meets the bar',
    },
    {
      id: 'ethics-kit',
      url: `${origin}/v1/pay/ethics`,
      asset: 'USD',
      amount_usd: 42,
      pay_uri: STRIPE_ETHICS_LINK,
      meets_first_42: true,
      note: 'live Fieldproof Ethics Check Word ZIP; one $42 Stripe payment meets the bar',
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
      pay_uri: STRIPE_PAYMENT_LINK,
      meets_first_42: true,
      note: 'HTML pay landing auto-opens the live $42 Stripe checkout; Gumroad overlay stays secondary',
    },
    {
      id: 'tip-uri',
      url: `${origin}/v1/pay/tip-jar.uri`,
      asset: 'USD',
      amount_usd: 42,
      pay_uri: GUMROAD_TIP,
      meets_first_42: true,
      note: 'text/uri-list of the live $42 tip jar on Gumroad; that checkout is PWYW listed at $42, not a different kit',
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
      note: 'canonical $42 quote: browsers get a live checkout that auto-opens Stripe; agents get a 402 with USDC plus card fallback',
    },
    {
      id: 'quote-42',
      url: `${origin}/v1/quote`,
      asset: 'USD',
      amount_usd: 42,
      meets_first_42: true,
      note: 'directory alias of /v1/offer; browsers get a live Stripe checkout; agents get 402 with 42 USDC plus card fallback',
    },
    {
      id: 'invoice-42',
      url: `${origin}/v1/invoice`,
      asset: 'USD',
      amount_usd: 42,
      meets_first_42: true,
      note: 'HTTP 200 multi-rail invoice; browsers auto-open the live $42 Stripe checkout; JSON and uri-list stay for agents',
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
      id: 'usdc-qr',
      url: `${origin}/v1/pay/usdc.png`,
      asset: 'USDC',
      amount_usd: 42,
      pay_to: payTo,
      network: c.network,
      pay_uri: usdcEip681(payTo),
      qr_url: usdcQrUrl(payTo),
      meets_first_42: true,
      note: '302 to a scannable QR of the 42 USDC EIP-681 invoice on Base',
    },
    {
      id: 'zelle',
      url: `${origin}/v1/pay/zelle`,
      asset: 'USD',
      amount_usd: 42,
      pay_to: ZELLE_EMAIL,
      pay_uri: zelleMailto(),
      meets_first_42: true,
      note: 'send $42 via Zelle to 3labsio@gmail.com memo Fieldproof; HTML pay instructions plus mailto URI',
    },
    {
      id: 'zelle-uri',
      url: `${origin}/v1/pay/zelle.uri`,
      asset: 'USD',
      amount_usd: 42,
      pay_to: ZELLE_EMAIL,
      pay_uri: zelleMailto(),
      meets_first_42: true,
      note: 'text/uri-list mailto invoice for $42 Zelle; agents open the first URI',
    },
    {
      id: 'zelle-qr',
      url: `${origin}/v1/pay/zelle.png`,
      asset: 'USD',
      amount_usd: 42,
      pay_to: ZELLE_EMAIL,
      pay_uri: zelleMailto(),
      qr_url: zelleQrUrl(),
      meets_first_42: true,
      note: '302 to a scannable QR of the $42 Zelle mailto invoice; one stranger Zelle meets the bar',
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
      qr_url: btcQrUrl(btc?.satsFor42 || null),
      meets_first_42: Boolean(btc?.satsFor42),
      note: btc?.satsFor42
        ? `send ${btc.satsFor42} sats (~$${GOAL_USD} at quoted spot); BIP21 pay_uri plus scannable QR`
        : 'public P2WPKH receive; ≥$42 of BTC at spot meets the bar; observed on mempool.space',
    },
    {
      id: 'bitcoin-qr',
      url: `${origin}/v1/pay/btc.png`,
      asset: 'BTC',
      amount_usd: 42,
      amount_sats: btc?.satsFor42 ?? null,
      pay_to: BTC_ADDRESS,
      pay_uri: btcBip21(btc?.satsFor42 || null),
      qr_url: btcQrUrl(btc?.satsFor42 || null),
      meets_first_42: true,
      note: '302 to a scannable QR of the live BIP-21 Bitcoin invoice; one ≥$42 on-chain receive meets the bar',
    },
  ];
}

/** Bazaar discovery declaration.
 *
 *  Two things here are load-bearing and were both wrong until 2026-08-16:
 *
 *  1. `info.input` uses `body`, not `bodyFields`. The spec's input schema sets
 *     `additionalProperties: false`, so one unrecognised key invalidates the declaration.
 *  2. `schema` validates `info` — NOT the request body. It previously described the
 *     {request, policy, policy_id} POST fields, which is a different object entirely, so it
 *     declared no `input` property at all. Facilitators MUST validate `info` against `schema`
 *     before cataloging, so that declaration could only ever be rejected.
 *
 *  A rejection is invisible except in the `EXTENSION-RESPONSES` header on verify/settle, which
 *  is why this survived: nothing 4xxs, the payment settles, the resource simply never appears.
 */
function bazaarExtension(origin) {
  return {
    bazaar: {
      info: {
        input: {
          type: 'http',
          method: 'POST',
          bodyType: 'json',
          body: {
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
        $schema: 'https://json-schema.org/draft/2020-12/schema',
        type: 'object',
        properties: {
          input: {
            type: 'object',
            properties: {
              type: { type: 'string', const: 'http' },
              method: { type: 'string', enum: ['POST', 'PUT', 'PATCH'] },
              bodyType: { type: 'string', enum: ['json', 'form-data', 'text'] },
              body: { type: 'object' },
              queryParams: { type: 'object', additionalProperties: { type: 'string' } },
              headers: { type: 'object', additionalProperties: { type: 'string' } },
            },
            required: ['type', 'method', 'bodyType', 'body'],
            additionalProperties: false,
          },
          output: {
            type: 'object',
            properties: {
              type: { type: 'string' },
              example: { type: 'object' },
            },
            required: ['type'],
          },
        },
        required: ['input'],
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
  // Optional ledger view: cumulative exposure the request alone cannot show. Same contract as
  // the MIT engine — committed_* plus intended_*, and a policy that asks for it without
  // getting it fails closed rather than falling through.
  const verdict = check(policy, parsed.request, parsed.ledger);
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
            transport: 'streamable-http',
            protocol: 'mcp',
            usage: 'POST JSON-RPC 2.0 here',
            name: 'Fieldproof Policy Gate',
            description: 'Deterministic policy verdicts plus one $42 checkout (USDC x402 or card).',
            price_usd: 42,
            currency: 'USDC',
            network: 'base',
            sponsor: `${url.origin}/v1/sponsor`,
            invoice: `${url.origin}/v1/invoice`,
            card_uri: `${url.origin}/v1/pay/card.uri`,
            usdc_uri: `${url.origin}/v1/pay/usdc.uri`,
            btc_uri: `${url.origin}/v1/pay/btc.uri`,
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
              'Deterministic allow / require_approval / deny verdicts for proposed agent actions. policy_example and policy_rules are free; policy_check quotes $0.005/check; first_42_sponsor returns the live $42 invoice (card_uri, usdc_uri, btc_uri, x402, Zelle). One $42 payment meets the first-$42 bar.',
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
            // Forward the ledger. The schema advertises it, so dropping it here would be a
            // parameter that exists only in documentation.
            if (c.free) return text(check(policy, req, args.ledger));
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
            const payTo = c.payTo || '0x07C2383008a9ed30581f27Db5531E19411c94fb3';
            let btc = null;
            try { btc = await observeBtc(); } catch { btc = null; }
            const invoice = fieldproofInvoice(url.origin, payTo, btc);
            return text({
              payment_required: !c.free,
              price_usd: 42,
              amount_atomic: quote.amount,
              endpoint: `${url.origin}/v1/sponsor`,
              pay_to: payTo,
              accepts: c.free ? [] : [paymentRequirementsV1(quote, `${url.origin}/v1/sponsor`)],
              fallback: stripeFallbackOffer(),
              invoice: `${url.origin}/v1/invoice`,
              card_uri: `${url.origin}/v1/pay/card.uri`,
              usdc_uri: `${url.origin}/v1/pay/usdc.uri`,
              btc_uri: `${url.origin}/v1/pay/btc.uri`,
              card: STRIPE_PAYMENT_LINK,
              methods: invoice.methods,
              how: 'Open card_uri or fallback.url for $42 card (also Cash App, Link, US bank, Klarna, Afterpay, Affirm). Fetch usdc_uri for 42 USDC EIP-681. Fetch btc_uri for BIP-21. Or POST /v1/sponsor with X-PAYMENT for 42 USDC on Base. One settlement meets the first-$42 bar.',
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
          funding: npmFunding(),
          checkouts: checkouts(c, url.origin),
        },
        { Link: paymentLinkHeader() },
        c.free
      );
    }

    if (request.method === 'GET' && (url.pathname === '/package.json' || url.pathname === '/.well-known/package.json')) {
      if (url.pathname === '/package.json' && wantsHtml(request)) {
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
          name: '@fieldproofhq/policy-gate',
          version: '0.2.0',
          description: 'Deterministic policy verdicts for agents. Pay $42 with card or 42 USDC on Base.',
          funding: npmFunding(),
          homepage: 'https://fieldproofhq.github.io/offer/',
          repository: { type: 'git', url: 'https://github.com/fieldproofhq/policy-gate' },
        },
        { Link: paymentLinkHeader() },
        true
      );
    }

    if (request.method === 'GET' && (url.pathname === '/pay' || url.pathname === '/pay/')) {
      if (wantsHtml(request)) {
        let btc = null;
        try { btc = await observeBtc(); } catch { btc = null; }
        return new Response(payIndexHtml(url.origin, btc), {
          status: 200,
          headers: { 'content-type': 'text/html; charset=utf-8', Link: paymentLinkHeader(), ...corsHeaders() },
        });
      }
      return Response.redirect(STRIPE_PAYMENT_LINK, 302);
    }

    if (request.method === 'GET' && (url.pathname === '/openapi.json' || url.pathname === '/.well-known/openapi.json')) {
      if (url.pathname === '/openapi.json' && wantsHtml(request)) {
        let btc = null;
        try { btc = await observeBtc(); } catch { btc = null; }
        return new Response(payIndexHtml(url.origin, btc), {
          status: 200,
          headers: { 'content-type': 'text/html; charset=utf-8', Link: paymentLinkHeader(), ...corsHeaders() },
        });
      }
      return json(200, openApiSpec(url.origin), { Link: paymentLinkHeader() }, true);
    }

    if (request.method === 'GET' && url.pathname === '/robots.txt') {
      if (wantsHtml(request)) {
        let btc = null;
        try { btc = await observeBtc(); } catch { btc = null; }
        return new Response(payIndexHtml(url.origin, btc), {
          status: 200,
          headers: { 'content-type': 'text/html; charset=utf-8', Link: paymentLinkHeader(), ...corsHeaders() },
        });
      }
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
      if (wantsHtml(request)) {
        let btc = null;
        try { btc = await observeBtc(); } catch { btc = null; }
        return new Response(payIndexHtml(url.origin, btc), {
          status: 200,
          headers: { 'content-type': 'text/html; charset=utf-8', Link: paymentLinkHeader(), ...corsHeaders() },
        });
      }
      const locs = [
        `${url.origin}/pay`,
        `${url.origin}/v1/pay`,
        `${url.origin}/v1/pay/card`,
        `${url.origin}/v1/pay/card.uri`,
        `${url.origin}/v1/pay/card.png`,
        `${url.origin}/v1/sponsor`,
        `${url.origin}/v1/offer`,
        `${url.origin}/v1/quote`,
        `${url.origin}/v1/invoice`,
        `${url.origin}/v1/pay/usdc.uri`,
        `${url.origin}/v1/pay/usdc.png`,
        `${url.origin}/v1/pay/btc.uri`,
        `${url.origin}/v1/pay/scan`,
        `${url.origin}/v1/pay/btc.png`,
        `${url.origin}/v1/pay/zelle.uri`,
        `${url.origin}/v1/pay/zelle.png`,
        `${url.origin}/v1/pay/pack.uri`,
        `${url.origin}/v1/pay/tip-jar.uri`,
        `${url.origin}/mcp`,
        `${url.origin}/skills/pay/SKILL.md`,
        `${url.origin}/.well-known/skills.json`,
        `${url.origin}/.well-known/x402`,
        `${url.origin}/.well-known/pay`,
        `${url.origin}/.well-known/agent-card.json`,
        `${url.origin}/openapi.json`,
        `${url.origin}/.well-known/ai-plugin.json`,
        `${url.origin}/.well-known/mcp.json`,
        `${url.origin}/.well-known/security.txt`,
        `${url.origin}/humans.txt`,
        `${url.origin}/.well-known/humans.txt`,
        `${url.origin}/.well-known/webfinger`,
        `${url.origin}/.well-known/host-meta`,
        `${url.origin}/.well-known/host-meta.json`,
        `${url.origin}/.well-known/did.json`,
        `${url.origin}/.well-known/nodeinfo`,
        `${url.origin}/nodeinfo/2.1`,
        `${url.origin}/.well-known/llms.txt`,
        `${url.origin}/llms-full.txt`,
        `${url.origin}/package.json`,
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
      if (url.pathname === '/llms.txt' && wantsHtml(request)) {
        let btc = null;
        try { btc = await observeBtc(); } catch { btc = null; }
        return new Response(payIndexHtml(url.origin, btc), {
          status: 200,
          headers: { 'content-type': 'text/html; charset=utf-8', Link: paymentLinkHeader(), ...corsHeaders() },
        });
      }
      const body = [
        '# Fieldproof',
        '',
        'Pay $42: https://buy.stripe.com/eVq4gA91U3Rr1Yt6z31sQ00',
        `Short pay URL: ${url.origin}/pay`,
        `Agent quote: ${url.origin}/v1/offer`,
        'Card, Cash App, Link, US bank debit, Klarna, Afterpay, Affirm.',
        'Store: https://store.3labs.io',
        `USDC/BTC/Zelle: ${url.origin}/v1/pay`,
        `Full list: ${url.origin}/llms-full.txt`,
        '',
      ].join('\n');
      return new Response(body, {
        status: 200,
        headers: { 'content-type': 'text/plain; charset=utf-8', Link: paymentLinkHeader(), ...corsHeaders() },
      });
    }

    if (request.method === 'GET' && (url.pathname === '/llms-full.txt' || url.pathname === '/.well-known/llms-full.txt')) {
      if (url.pathname === '/llms-full.txt' && wantsHtml(request)) {
        let btc = null;
        try { btc = await observeBtc(); } catch { btc = null; }
        return new Response(payIndexHtml(url.origin, btc), {
          status: 200,
          headers: { 'content-type': 'text/html; charset=utf-8', Link: paymentLinkHeader(), ...corsHeaders() },
        });
      }
      const body = [
        '# Fieldproof — every live $42 checkout',
        '',
        'One stranger payment of $42 (or 42 USDC / equivalent BTC) meets the first-income bar.',
        '',
        '## Card / bank / wallets',
        `- Stripe Payment Link: ${STRIPE_PAYMENT_LINK}`,
        `- Card URI (text/uri-list): ${url.origin}/v1/pay/card.uri`,
        `- Card QR (scannable): ${url.origin}/v1/pay/card.png`,
        '- Methods: card, Cash App, Link, US bank debit, Klarna, Afterpay, Affirm',
        `- Mission offer (stays on the page; card, pack, scan): https://fieldproofhq.github.io/offer/`,
        `- Worker short URL (HTML stays on the page): ${url.origin}/pay`,
        `- Agent quote (GET or POST 402): ${url.origin}/v1/offer`,
        `- Directory quote alias (GET or POST 402): ${url.origin}/v1/quote`,
        `- Multi-rail invoice (HTML stays on the page): ${url.origin}/v1/invoice`,
        `- MCP pay tool (first_42_sponsor): ${url.origin}/mcp`,
        `- Agent skill: ${url.origin}/skills/pay/SKILL.md`,
        `- npm funding (package.json): ${url.origin}/package.json`,
        `- security.txt: ${url.origin}/.well-known/security.txt`,
        `- humans.txt: ${url.origin}/humans.txt`,
        `- WebFinger: ${url.origin}/.well-known/webfinger?resource=acct:pay@${new URL(url.origin).host}`,
        `- NodeInfo: ${url.origin}/.well-known/nodeinfo`,
        `- host-meta.json: ${url.origin}/.well-known/host-meta.json`,
        `- did:web: ${url.origin}/.well-known/did.json`,
        '',
        '## Store',
        '- Store: https://store.3labs.io',
        '- $42 Governance Pack: https://store.3labs.io/l/agentic-ai-governance-pack?wanted=true',
        `- Pack URI (text/uri-list): ${url.origin}/v1/pay/pack.uri`,
        '- $42 tip jar: https://store.3labs.io/l/tip-jar?wanted=true',
        `- Tip-jar URI (text/uri-list): ${url.origin}/v1/pay/tip-jar.uri`,
        '',
        '## Crypto / Zelle',
        `- 42 USDC on Base: ${url.origin}/v1/pay/usdc`,
        `- 42 USDC EIP-681 (text/uri-list): ${url.origin}/v1/pay/usdc.uri`,
        `- 42 USDC QR (scannable): ${url.origin}/v1/pay/usdc.png`,
        `- POST /v1/sponsor x402: ${url.origin}/v1/sponsor`,
        `- Bitcoin: ${url.origin}/v1/pay/btc`,
        `- Bitcoin BIP-21 (text/uri-list): ${url.origin}/v1/pay/btc.uri`,
        `- Scan board (USDC + BTC + Zelle QRs): ${url.origin}/v1/pay/scan`,
        `- Bitcoin QR (scannable): ${url.origin}/v1/pay/btc.png`,
        `- Zelle $42 to 3labsio@gmail.com: ${url.origin}/v1/pay/zelle`,
        `- Zelle mailto (text/uri-list): ${url.origin}/v1/pay/zelle.uri`,
        `- Zelle QR (scannable): ${url.origin}/v1/pay/zelle.png`,
        '',
        'Observer: GET /v1/received. A 402 or HTTP 200 is not income.',
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

      // This route is documented as "an index of every live $42 rail", and it was serving HTML
      // with a meta-refresh and a location.replace to one checkout, for every Accept header.
      // So an agent asking for JSON could not enumerate anything, and a human never saw the
      // USDC / Bitcoin / Zelle options at all — the rails that meet $42 on their own.
      // Machines get the index as data; browsers get the page.
      const accept = request.headers.get('accept') || '';
      if (!accept.includes('text/html')) {
        const payTo = c.payTo || '0x07C2383008a9ed30581f27Db5531E19411c94fb3';
        return json(200, {
          endpoint: `${url.origin}/v1/pay`,
          goal_usd: GOAL_USD,
          note: 'Every rail below is live. Any one of the $42 rails meets the bar alone. Self-payments are excluded from the public counter.',
          rails: [
            {
              id: 'x402-sponsor', amount_usd: 42, asset: 'USDC', network: 'Base (eip155:8453)',
              method: 'POST', url: `${url.origin}/v1/sponsor`, pay_to: payTo,
              meets_goal_alone: true, note: 'One settlement. GET the same path for docs.',
            },
            {
              id: 'usdc-direct', amount_usd: 42, asset: 'USDC', network: 'Base (eip155:8453)',
              pay_to: payTo, pay_uri: usdcEip681(payTo), meets_goal_alone: true,
            },
            {
              id: 'bitcoin', amount_usd: 42, asset: 'BTC',
              pay_to: btc?.address ?? null, pay_uri: btc?.uri ?? null,
              meets_goal_alone: true, live: Boolean(btc?.address),
            },
            {
              id: 'card', amount_usd: 42, asset: 'USD', url: STRIPE_PAYMENT_LINK,
              meets_goal_alone: true,
              note: 'Card checkout. Delivers the Ethics Check and C-suite Word kits — NOT the Agentic AI Governance Pack. For the pack, use store.3labs.io.',
            },
            {
              id: 'zelle', amount_usd: 42, asset: 'USD',
              pay_to: '3labsio@gmail.com', pay_uri: `${url.origin}/v1/pay/zelle.uri`,
              meets_goal_alone: true, note: 'Zero fees. US bank to US bank, memo "Fieldproof".',
            },
            {
              id: 'governance-pack', amount_usd: 42, asset: 'USD',
              url: 'https://store.3labs.io/l/agentic-ai-governance-pack',
              meets_goal_alone: true, note: 'Seven editable Word documents. One of the seven is free to read first.',
            },
            {
              id: 'tip-jar', amount_usd: 42, asset: 'USD',
              url: 'https://store.3labs.io/l/tip-jar',
              meets_goal_alone: true, note: 'Fuel the experiment. Buys nothing; it is a tip.',
            },
            {
              id: 'x402-check', amount_usd: 0.005, asset: 'USDC', network: 'Base (eip155:8453)',
              method: 'POST', url: `${url.origin}/v1/check`,
              meets_goal_alone: false, checks_for_42: 8400,
            },
          ],
          free_first: {
            worked_verdicts: `${url.origin}/v1/example`,
            full_ruleset: `${url.origin}/v1/policies`,
          },
        });
      }
      return new Response(payIndexHtml(url.origin, btc), { status: 200, headers: { 'content-type': 'text/html; charset=utf-8', ...corsHeaders() } });
    }

    if (request.method === 'GET' && (url.pathname === '/v1/pay/scan' || url.pathname === '/v1/pay/scan/')) {
      let btc = null;
      try { btc = await observeBtc(); } catch { btc = null; }
      return new Response(scanPaysHtml(url.origin, btc), {
        status: 200,
        headers: { 'content-type': 'text/html; charset=utf-8', Link: paymentLinkHeader(), ...corsHeaders() },
      });
    }

    if (request.method === 'GET' && url.pathname === '/v1/pay/x402') {
      const payTo = c.payTo || '0x07C2383008a9ed30581f27Db5531E19411c94fb3';
      const price = c.priceUsd || '0.005';
      const checks = Number(price) > 0 ? Math.ceil(42 / Number(price)) : 8400;
      const payUri = usdcEip681(payTo);
      const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Pay $42 via x402 — Fieldproof</title>
<link rel="payment" href="${STRIPE_PAYMENT_LINK}">
</head><body style="font-family:system-ui,sans-serif;max-width:44rem;margin:2rem auto;padding:0 1rem;line-height:1.5;background:#f4efe6;color:#111">
<h1>Pay $42 via x402</h1>
<p>One transfer of <strong>42 USDC</strong> on <strong>Base</strong> meets the bar. Agents settle the same amount via <code>POST /v1/sponsor</code>. This page does not open card checkout.</p>
${walletPayControls(payTo, payUri)}
<p><a href="${url.origin}/v1/sponsor" style="display:inline-block;background:#111;color:#fff;text-decoration:none;padding:.7rem 1.1rem;border-radius:999px;font-weight:600">Open the 42 USDC checkout</a></p>
<p><a href="${payUri}">Open in wallet (EIP-681)</a></p>
<pre style="white-space:pre-wrap;overflow:auto">curl -s -D - -o /dev/null -X POST ${url.origin}/v1/sponsor</pre>
<p>Pay to <code>${payTo}</code> on <code>${c.network || 'eip155:8453'}</code>. Discovery: <a href="/.well-known/x402">/.well-known/x402</a>.</p>
<p>Per-check path (does not meet $42 alone): agents pay <strong>$${price}</strong> per <code>POST /v1/check</code> (${checks} checks = $42). Evaluate free first: <a href="/v1/example">GET /v1/example</a>.</p>
<pre style="white-space:pre-wrap;overflow:auto">curl -s -D - -o /dev/null -X POST ${url.origin}/v1/check \\
  -H "content-type: application/json" \\
  -d '{"policy_id":"default-action-tiers","request":{"action":"docs.read"}}'</pre>
<p>After settlement, check <a href="/v1/received">GET /v1/received</a>.</p>
${cardFallbackHtml()}
</body></html>`;
      return new Response(html, { status: 200, headers: { 'content-type': 'text/html; charset=utf-8', Link: paymentLinkHeader(), ...corsHeaders() } });
    }

    if (request.method === 'GET' && (url.pathname === '/v1/pay/card.uri' || url.pathname === '/v1/pay/card.txt')) {
      return uriListResponse(STRIPE_PAYMENT_LINK);
    }

    if (request.method === 'GET' && (url.pathname === '/v1/pay/card.png' || url.pathname === '/v1/pay/card.qr')) {
      return Response.redirect(stripeQrUrl(), 302);
    }

    if (request.method === 'GET' && url.pathname === '/v1/pay/card') {
      if (wantsUriList(request)) return uriListResponse(STRIPE_PAYMENT_LINK);
      if (wantsJson(request)) {
        return json(
          200,
          {
            scheme: 'stripe',
            asset: 'USD',
            amountUsd: GOAL_USD,
            uri: STRIPE_PAYMENT_LINK,
            url: STRIPE_PAYMENT_LINK,
            methods: ['card', 'cashapp', 'link', 'us_bank_account', 'klarna', 'afterpay_clearpay', 'affirm'],
            card: STRIPE_PAYMENT_LINK,
            zips: { cfo: CFO_ZIP, coo: COO_ZIP, cto: CTO_ZIP, ciso: CISO_ZIP, ethics: ETHICS_ZIP },
          },
          { Link: paymentLinkHeader() },
          true
        );
      }
      const qrUrl = `https://api.qrserver.com/v1/create-qr-code/?size=240x240&data=${encodeURIComponent(STRIPE_PAYMENT_LINK)}`;
      const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Pay $42 with card — Fieldproof</title>
<link rel="payment" href="${STRIPE_PAYMENT_LINK}">
</head><body style="font-family:system-ui,sans-serif;max-width:40rem;margin:2rem auto;padding:0 1rem;line-height:1.5;background:#f4efe6;color:#111">
<h1>Pay $42 with card</h1>
<p>This page stays here so you can pick a rail. Card checkout delivers the Ethics Check and C-suite Word ZIPs, not the Governance Pack. <strong>Card</strong>, <strong>Cash App</strong>, <strong>Link</strong>, <strong>US bank debit</strong>, <strong>Klarna</strong>, <strong>Afterpay</strong>, or <strong>Affirm</strong>.</p>
<p><a href="${STRIPE_PAYMENT_LINK}" style="display:inline-block;background:#111;color:#fff;text-decoration:none;padding:.7rem 1.1rem;border-radius:999px;font-weight:600">Pay $42 with card</a></p>
<p><a href="${STRIPE_PAYMENT_LINK}"><img src="https://api.qrserver.com/v1/create-qr-code/?size=240x240&data=${encodeURIComponent(STRIPE_PAYMENT_LINK)}" width="240" height="240" alt="QR code for the $42 Stripe checkout"></a></p>
<p>Direct: <a href="${STRIPE_PAYMENT_LINK}">${STRIPE_PAYMENT_LINK}</a></p>
<p>After a card payment, download: <a href="${CFO_ZIP}">CFO kit</a> · <a href="${COO_ZIP}">COO kit</a> · <a href="${CTO_ZIP}">CTO kit</a> · <a href="${CISO_ZIP}">CISO kit</a> · <a href="${ETHICS_ZIP}">Ethics Check kit</a>.</p>
<p>Want the pack instead? <a href="${GUMROAD_PACK}">Buy the $42 pack</a>. Scan: <a href="${url.origin}/v1/pay/scan">USDC / BTC / Zelle</a>. Also: <a href="https://store.3labs.io">store.3labs.io</a> · <a href="${url.origin}/v1/pay/usdc">42 USDC</a> · <a href="${url.origin}/v1/pay/btc">Bitcoin</a>.</p>
</body></html>`;
      return new Response(html, { status: 200, headers: { 'content-type': 'text/html; charset=utf-8', Link: paymentLinkHeader(), ...corsHeaders() } });
    }

    if (request.method === 'GET' && (url.pathname === '/v1/pay/pack.uri' || url.pathname === '/v1/pay/pack.txt')) {
      return uriListResponse(GUMROAD_PACK);
    }

    if (request.method === 'GET' && url.pathname === '/v1/pay/pack') {
      const checkout = GUMROAD_PACK;
      if (wantsUriList(request)) return uriListResponse(GUMROAD_PACK);
      if (wantsJson(request)) {
        return json(
          200,
          {
            scheme: 'gumroad',
            asset: 'USD',
            amountUsd: GOAL_USD,
            uri: checkout,
            url: checkout,
            product: 'agentic-ai-governance-pack',
            card: STRIPE_PAYMENT_LINK,
            gumroad: checkout,
          },
          { Link: paymentLinkHeader() },
          true
        );
      }
      const overlay = 'https://fieldproof.gumroad.com/l/agentic-ai-governance-pack';
      const cover = 'https://public-files.gumroad.com/k5vh8fw0i5jkr4pzz9zveemcfjax';
      const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Buy the $42 Governance Pack — Fieldproof</title>
<link rel="payment" href="${checkout}">
<script src="https://gumroad.com/js/gumroad.js"></script></head><body style="font-family:system-ui,sans-serif;max-width:40rem;margin:2rem auto;padding:0 1rem;line-height:1.5;background:#f4efe6;color:#111">
<h1>Buy the $42 Governance Pack</h1>
<p>This page stays here so you can pick a rail. Seven editable templates this AI-run business actually operates under. <strong>$42</strong>. No Fieldproof account. The file is attached on Gumroad and downloads after payment. Generic card checkout is a different product.</p>
<p><a href="${checkout}"><img src="${cover}" alt="Agentic AI Governance Pack" width="640" height="336" style="display:block;width:100%;height:auto;border-radius:12px;background:#111"></a></p>
<p style="font-size:1.25rem;font-weight:700">$42</p>
<p><a class="gumroad-button" href="${overlay}">Buy the $42 pack</a> <a href="${STRIPE_PAYMENT_LINK}" target="_blank" rel="noopener noreferrer" style="display:inline-block;background:#111;color:#fff;text-decoration:none;padding:.7rem 1.1rem;border-radius:999px;font-weight:600">Pay $42 with card</a> for the Ethics Check and C-suite Word ZIPs (not this pack).</p>
${cardFallbackHtml()}
<p>Store: <a href="${checkout}">store.3labs.io pack</a>. Scan: <a href="${url.origin}/v1/pay/scan">USDC / BTC / Zelle</a>.</p>
</body></html>`;
      return new Response(html, { status: 200, headers: { 'content-type': 'text/html; charset=utf-8', Link: paymentLinkHeader(), ...corsHeaders() } });
    }

    if (request.method === 'GET' && (url.pathname === '/v1/pay/cfo' || url.pathname === '/v1/pay/cfo.uri')) {
      if (url.pathname === '/v1/pay/cfo.uri' || wantsUriList(request)) return uriListResponse(STRIPE_CFO_LINK);
      if (wantsJson(request)) {
        return json(200, { scheme: 'stripe', asset: 'USD', amountUsd: GOAL_USD, uri: STRIPE_CFO_LINK, url: STRIPE_CFO_LINK, zip: CFO_ZIP, product: 'fractional-cfo-launch-kit' }, { Link: paymentLinkHeader() }, true);
      }
      const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Buy the $42 CFO Launch Kit — Fieldproof</title>
<link rel="payment" href="${STRIPE_CFO_LINK}">
</head><body style="font-family:system-ui,sans-serif;max-width:40rem;margin:2rem auto;padding:0 1rem;line-height:1.5;background:#f4efe6;color:#111">
<h1>Buy the $42 Fractional CFO Launch Kit</h1>
<p>This page stays here so you can pick a rail. Six editable Word templates for observing received income by rail.</p>
<p style="font-size:1.25rem;font-weight:700">$42</p>
<p><a href="${STRIPE_CFO_LINK}" style="display:inline-block;background:#111;color:#fff;text-decoration:none;padding:.7rem 1.1rem;border-radius:999px;font-weight:600">Pay $42 with card</a></p>
<p>After payment, download: <a href="${CFO_ZIP}">Fractional-CFO-Launch-Kit.zip</a>. Agent contract: <a href="https://fieldproofhq.github.io/csuite/cfo/">csuite/cfo</a>. Pack: <a href="${GUMROAD_PACK}">Buy the $42 pack</a>. Scan: <a href="${url.origin}/v1/pay/scan">USDC / BTC / Zelle</a>.</p>
</body></html>`;
      return new Response(html, { status: 200, headers: { 'content-type': 'text/html; charset=utf-8', Link: paymentLinkHeader(), ...corsHeaders() } });
    }

    if (request.method === 'GET' && (url.pathname === '/v1/pay/coo' || url.pathname === '/v1/pay/coo.uri')) {
      if (url.pathname === '/v1/pay/coo.uri' || wantsUriList(request)) return uriListResponse(STRIPE_COO_LINK);
      if (wantsJson(request)) {
        return json(200, { scheme: 'stripe', asset: 'USD', amountUsd: GOAL_USD, uri: STRIPE_COO_LINK, url: STRIPE_COO_LINK, zip: COO_ZIP, product: 'fractional-coo-launch-kit' }, { Link: paymentLinkHeader() }, true);
      }
      const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Buy the $42 COO Launch Kit — Fieldproof</title>
<link rel="payment" href="${STRIPE_COO_LINK}">
</head><body style="font-family:system-ui,sans-serif;max-width:40rem;margin:2rem auto;padding:0 1rem;line-height:1.5;background:#f4efe6;color:#111">
<h1>Buy the $42 Fractional COO Launch Kit</h1>
<p>This page stays here so you can pick a rail. Six editable Word templates for cadence, human gates, contract boards, delivery SLAs, incident escalation, and a Friday ops review.</p>
<p style="font-size:1.25rem;font-weight:700">$42</p>
<p><a href="${STRIPE_COO_LINK}" style="display:inline-block;background:#111;color:#fff;text-decoration:none;padding:.7rem 1.1rem;border-radius:999px;font-weight:600">Pay $42 with card</a></p>
<p>After payment, download: <a href="${COO_ZIP}">Fractional-COO-Launch-Kit.zip</a>. Agent contract: <a href="https://fieldproofhq.github.io/csuite/coo/">csuite/coo</a>. Pack: <a href="${GUMROAD_PACK}">Buy the $42 pack</a>. Scan: <a href="${url.origin}/v1/pay/scan">USDC / BTC / Zelle</a>.</p>
</body></html>`;
      return new Response(html, { status: 200, headers: { 'content-type': 'text/html; charset=utf-8', Link: paymentLinkHeader(), ...corsHeaders() } });
    }

    if (request.method === 'GET' && (url.pathname === '/v1/pay/cto' || url.pathname === '/v1/pay/cto.uri')) {
      if (url.pathname === '/v1/pay/cto.uri' || wantsUriList(request)) return uriListResponse(STRIPE_CTO_LINK);
      if (wantsJson(request)) {
        return json(200, { scheme: 'stripe', asset: 'USD', amountUsd: GOAL_USD, uri: STRIPE_CTO_LINK, url: STRIPE_CTO_LINK, zip: CTO_ZIP, product: 'fractional-cto-launch-kit' }, { Link: paymentLinkHeader() }, true);
      }
      const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Buy the $42 CTO Launch Kit — Fieldproof</title>
<link rel="payment" href="${STRIPE_CTO_LINK}">
</head><body style="font-family:system-ui,sans-serif;max-width:40rem;margin:2rem auto;padding:0 1rem;line-height:1.5;background:#f4efe6;color:#111">
<h1>Buy the $42 Fractional CTO Launch Kit</h1>
<p>This page stays here so you can pick a rail. Six editable Word templates for stack cadence, public URL audits, content negotiation, checkout HTML vs JSON, observability, and a Friday tech review.</p>
<p style="font-size:1.25rem;font-weight:700">$42</p>
<p><a href="${STRIPE_CTO_LINK}" style="display:inline-block;background:#111;color:#fff;text-decoration:none;padding:.7rem 1.1rem;border-radius:999px;font-weight:600">Pay $42 with card</a></p>
<p>After payment, download: <a href="${CTO_ZIP}">Fractional-CTO-Launch-Kit.zip</a>. Agent contract: <a href="https://fieldproofhq.github.io/csuite/cto/">csuite/cto</a>. Pack: <a href="${GUMROAD_PACK}">Buy the $42 pack</a>. Scan: <a href="${url.origin}/v1/pay/scan">USDC / BTC / Zelle</a>.</p>
</body></html>`;
      return new Response(html, { status: 200, headers: { 'content-type': 'text/html; charset=utf-8', Link: paymentLinkHeader(), ...corsHeaders() } });
    }

    if (request.method === 'GET' && (url.pathname === '/v1/pay/ciso' || url.pathname === '/v1/pay/ciso.uri')) {
      if (url.pathname === '/v1/pay/ciso.uri' || wantsUriList(request)) return uriListResponse(STRIPE_CISO_LINK);
      if (wantsJson(request)) {
        return json(200, { scheme: 'stripe', asset: 'USD', amountUsd: GOAL_USD, uri: STRIPE_CISO_LINK, url: STRIPE_CISO_LINK, zip: CISO_ZIP, product: 'fractional-ciso-launch-kit' }, { Link: paymentLinkHeader() }, true);
      }
      const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Buy the $42 CISO Launch Kit — Fieldproof</title>
<link rel="payment" href="${STRIPE_CISO_LINK}">
</head><body style="font-family:system-ui,sans-serif;max-width:40rem;margin:2rem auto;padding:0 1rem;line-height:1.5;background:#f4efe6;color:#111">
<h1>Buy the $42 Fractional CISO Launch Kit</h1>
<p>This page stays here so you can pick a rail. Six editable Word templates for action tiers, default-deny, MCP connect review, incident halt-and-resume, and a Friday verdict review.</p>
<p style="font-size:1.25rem;font-weight:700">$42</p>
<p><a href="${STRIPE_CISO_LINK}" style="display:inline-block;background:#111;color:#fff;text-decoration:none;padding:.7rem 1.1rem;border-radius:999px;font-weight:600">Pay $42 with card</a></p>
<p>After payment, download: <a href="${CISO_ZIP}">Fractional-CISO-Launch-Kit.zip</a>. Agent contract: <a href="https://fieldproofhq.github.io/csuite/ciso/">csuite/ciso</a>. Pack: <a href="${GUMROAD_PACK}">Buy the $42 pack</a>. Scan: <a href="${url.origin}/v1/pay/scan">USDC / BTC / Zelle</a>.</p>
</body></html>`;
      return new Response(html, { status: 200, headers: { 'content-type': 'text/html; charset=utf-8', Link: paymentLinkHeader(), ...corsHeaders() } });
    }

    if (request.method === 'GET' && (url.pathname === '/v1/pay/ethics' || url.pathname === '/v1/pay/ethics.uri')) {
      if (url.pathname === '/v1/pay/ethics.uri' || wantsUriList(request)) return uriListResponse(STRIPE_ETHICS_LINK);
      if (wantsJson(request)) {
        return json(200, { scheme: 'stripe', asset: 'USD', amountUsd: GOAL_USD, uri: STRIPE_ETHICS_LINK, url: STRIPE_ETHICS_LINK, zip: ETHICS_ZIP, product: 'ethics-check-launch-kit' }, { Link: paymentLinkHeader() }, true);
      }
      const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Buy the $42 Ethics Check Kit — Fieldproof</title>
<link rel="payment" href="${STRIPE_ETHICS_LINK}">
</head><body style="font-family:system-ui,sans-serif;max-width:40rem;margin:2rem auto;padding:0 1rem;line-height:1.5;background:#f4efe6;color:#111">
<h1>Buy the $42 Fieldproof Ethics Check Launch Kit</h1>
<p>This page stays here so you can pick a rail. Six editable Word templates for the seven canons, inclusion and voice, human-LLM team dynamics, team-size design, and a Friday ethics review. Canons stay free at GET /v1/canons.</p>
<p style="font-size:1.25rem;font-weight:700">$42</p>
<p><a href="${STRIPE_ETHICS_LINK}" style="display:inline-block;background:#111;color:#fff;text-decoration:none;padding:.7rem 1.1rem;border-radius:999px;font-weight:600">Pay $42 with card</a></p>
<p>After payment, download: <a href="${ETHICS_ZIP}">Fieldproof-Ethics-Check-Launch-Kit.zip</a>. Agent contract: <a href="https://fieldproofhq.github.io/ethics/">ethics</a>. Pack: <a href="${GUMROAD_PACK}">Buy the $42 pack</a>. Scan: <a href="${url.origin}/v1/pay/scan">USDC / BTC / Zelle</a>.</p>
</body></html>`;
      return new Response(html, { status: 200, headers: { 'content-type': 'text/html; charset=utf-8', Link: paymentLinkHeader(), ...corsHeaders() } });
    }

    if (request.method === 'GET' && url.pathname === '/v1/pay/cmo') {
      const checkout = 'https://store.3labs.io/l/fractional-cmo-launch-kit?wanted=true';
      const overlay = 'https://fieldproof.gumroad.com/l/fractional-cmo-launch-kit';
      const cover = 'https://public-files.gumroad.com/q8ndyh3mpngn25hk15p4pwuby0my';
      const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Buy the $39 CMO Launch Kit — Fieldproof</title>
<meta http-equiv="refresh" content="0;url=${checkout}">
<link rel="payment" href="${checkout}">
<script src="https://gumroad.com/js/gumroad.js"></script></head><body style="font-family:system-ui,sans-serif;max-width:40rem;margin:2rem auto;padding:0 1rem;line-height:1.5;background:#f4efe6;color:#111">
<h1>Buy the $39 Fractional CMO Launch Kit</h1>
<p>Opening the $39 CMO kit. Land a fractional CMO practice in 30 days — or load the same kit so an agent can hold the seat. The file is attached on Gumroad and downloads after payment. Generic card checkout is a different product.</p>
<p><a href="${checkout}"><img src="${cover}" alt="Fractional CMO Launch Kit" width="640" height="336" style="display:block;width:100%;height:auto;border-radius:12px;background:#111"></a></p>
<p style="font-size:1.25rem;font-weight:700">$39</p>
<p><a class="gumroad-button" href="${overlay}" style="display:inline-block;background:#111;color:#fff;text-decoration:none;padding:.7rem 1.1rem;border-radius:999px;font-weight:600">Buy the $39 CMO kit</a> <a href="${STRIPE_PAYMENT_LINK}" target="_blank" rel="noopener noreferrer" style="display:inline-block;background:#111;color:#fff;text-decoration:none;padding:.7rem 1.1rem;border-radius:999px;font-weight:600">Pay $42 with card</a> for the Ethics Check and C-suite Word ZIPs (not this CMO kit).</p>
${cardFallbackHtml()}
<p>If nothing happens, use the button. Agent contract: <a href="https://fieldproofhq.github.io/csuite/cmo/">fieldproofhq.github.io/csuite/cmo</a>. Scan: <a href="${url.origin}/v1/pay/scan">USDC / BTC / Zelle</a>.</p>
<script>location.replace(${JSON.stringify(checkout)});</script>
</body></html>`;
      return new Response(html, { status: 200, headers: { 'content-type': 'text/html; charset=utf-8', Link: paymentLinkHeader(), ...corsHeaders() } });
    }

    if (request.method === 'GET' && (url.pathname === '/v1/pay/tip-jar.uri' || url.pathname === '/v1/pay/tip-jar.txt')) {
      return uriListResponse(GUMROAD_TIP);
    }

    if (request.method === 'GET' && url.pathname === '/v1/pay/tip-jar') {
      const checkout = GUMROAD_TIP;
      if (wantsUriList(request)) return uriListResponse(GUMROAD_TIP);
      if (wantsJson(request)) {
        return json(
          200,
          {
            scheme: 'gumroad',
            asset: 'USD',
            amountUsd: GOAL_USD,
            uri: checkout,
            url: checkout,
            product: 'tip-jar',
            card: STRIPE_PAYMENT_LINK,
            gumroad: checkout,
          },
          { Link: paymentLinkHeader() },
          true
        );
      }
      const overlay = 'https://fieldproof.gumroad.com/l/tip-jar';
      const cover = 'https://public-files.gumroad.com/5u12tofcw2kg35lga2na9ri6cba3';
      const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Support Fieldproof $42 — tip jar</title>
<meta http-equiv="refresh" content="0;url=${checkout}">
<link rel="payment" href="${checkout}">
<script src="https://gumroad.com/js/gumroad.js"></script></head><body style="font-family:system-ui,sans-serif;max-width:40rem;margin:2rem auto;padding:0 1rem;line-height:1.5;background:#f4efe6;color:#111">
<h1>Support Fieldproof — $42 tip jar</h1>
<p>Opening the $42 tip jar. Listed at <strong>$42</strong>. Pay more if you want. No Fieldproof account. Generic card checkout is a different product.</p>
<p><a href="${checkout}"><img src="${cover}" alt="Fieldproof tip jar" width="640" height="336" style="display:block;width:100%;height:auto;border-radius:12px;background:#111"></a></p>
<p style="font-size:1.25rem;font-weight:700">$42+</p>
<p><a class="gumroad-button" href="${overlay}">Support $42 on Gumroad</a> <a href="${STRIPE_PAYMENT_LINK}" target="_blank" rel="noopener noreferrer" style="display:inline-block;background:#111;color:#fff;text-decoration:none;padding:.7rem 1.1rem;border-radius:999px;font-weight:600">Pay $42 with card</a> for the Ethics Check and C-suite Word ZIPs (not this tip).</p>
${cardFallbackHtml()}
<p>If nothing happens, use the button. Store: <a href="${checkout}">store.3labs.io/l/tip-jar</a>. Scan: <a href="${url.origin}/v1/pay/scan">USDC / BTC / Zelle</a>.</p>
<script>location.replace(${JSON.stringify(checkout)});</script>
</body></html>`;
      return new Response(html, { status: 200, headers: { 'content-type': 'text/html; charset=utf-8', Link: paymentLinkHeader(), ...corsHeaders() } });
    }

    if (request.method === 'GET' && (url.pathname === '/v1/pay/btc.uri' || url.pathname === '/v1/pay/btc.txt')) {
      let btc = null;
      try { btc = await observeBtc(); } catch { btc = null; }
      return uriListResponse(btcBip21(btc?.satsFor42 || null));
    }

    if (request.method === 'GET' && (url.pathname === '/v1/pay/btc.png' || url.pathname === '/v1/pay/btc.qr')) {
      let btc = null;
      try { btc = await observeBtc(); } catch { btc = null; }
      return Response.redirect(btcQrUrl(btc?.satsFor42 || null), 302);
    }

    if (request.method === 'GET' && url.pathname === '/v1/pay/btc') {
      let btc = null;
      try { btc = await observeBtc(); } catch { btc = null; }
      const sats = btc?.satsFor42 || null;
      const payUri = btcBip21(sats);
      if (wantsUriList(request)) return uriListResponse(payUri);
      if (wantsJson(request)) {
        return json(
          200,
          {
            scheme: 'bip21',
            asset: 'BTC',
            amountUsd: GOAL_USD,
            amountSats: sats,
            priceUsd: btc?.priceUsd ?? null,
            payTo: BTC_ADDRESS,
            uri: payUri,
            qr: `https://api.qrserver.com/v1/create-qr-code/?size=240x240&data=${encodeURIComponent(payUri)}`,
            card: STRIPE_PAYMENT_LINK,
          },
          { Link: paymentLinkHeader() },
          true
        );
      }
      const qrUrl = `https://api.qrserver.com/v1/create-qr-code/?size=240x240&data=${encodeURIComponent(payUri)}`;
      const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Pay $42 in Bitcoin — Fieldproof</title>
<meta http-equiv="refresh" content="0;url=${payUri}">
<link rel="payment" href="${STRIPE_PAYMENT_LINK}">
</head><body style="font-family:system-ui,sans-serif;max-width:40rem;margin:2rem auto;padding:0 1rem;line-height:1.5;background:#f4efe6;color:#111">
<h1>Pay $42 in Bitcoin</h1>
<p>Opening wallet. Send <strong>${sats ? sats + ' sats' : 'enough BTC to be worth $42'}</strong>${btc?.priceUsd ? ` (~$${GOAL_USD} at $${btc.priceUsd}/BTC)` : ''} to the public address below. Scan the QR if your wallet does not open.</p>
<p><a href="${payUri}" id="fp-btc-open" style="display:inline-block;background:#111;color:#fff;text-decoration:none;padding:.7rem 1.1rem;border-radius:999px;font-weight:600">Open in wallet (BIP21)</a></p>
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
(function(){
  var PAY_URI = ${JSON.stringify(payUri)};
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(PAY_URI).catch(function(){});
  }
  if (PAY_URI) location.replace(PAY_URI);
})();
</script>
</body></html>`;
      return new Response(html, { status: 200, headers: { 'content-type': 'text/html; charset=utf-8', Link: paymentLinkHeader(), ...corsHeaders() } });
    }

    if (request.method === 'GET' && (url.pathname === '/v1/pay/zelle.uri' || url.pathname === '/v1/pay/zelle.txt')) {
      return uriListResponse(zelleMailto());
    }

    if (request.method === 'GET' && (url.pathname === '/v1/pay/zelle.png' || url.pathname === '/v1/pay/zelle.qr')) {
      return Response.redirect(zelleQrUrl(), 302);
    }

    if (request.method === 'GET' && url.pathname === '/v1/pay/zelle') {
      const payUri = zelleMailto();
      if (wantsUriList(request)) return uriListResponse(payUri);
      if (wantsJson(request)) {
        return json(
          200,
          {
            scheme: 'zelle',
            asset: 'USD',
            amountUsd: GOAL_USD,
            payTo: ZELLE_EMAIL,
            memo: 'Fieldproof',
            uri: payUri,
            card: STRIPE_PAYMENT_LINK,
          },
          { Link: paymentLinkHeader() },
          true
        );
      }
      const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Send $42 via Zelle — Fieldproof</title>
<meta http-equiv="refresh" content="0;url=${payUri}">
<link rel="payment" href="${STRIPE_PAYMENT_LINK}">
</head><body style="font-family:system-ui,sans-serif;max-width:40rem;margin:2rem auto;padding:0 1rem;line-height:1.5;background:#f4efe6;color:#111">
<h1>Send $42 via Zelle</h1>
<p>Opening the $42 memo. Send <strong>$42 USD</strong> via Zelle. Zero fees. No Fieldproof account. Scan the QR in a banking app that reads mailto invoices.</p>
<p><img src="${zelleQrUrl()}" width="240" height="240" alt="QR code for $42 Zelle to 3labsio@gmail.com"></p>
<p>In your US banking app, open Zelle and send:</p>
<ul>
<li>Amount: <strong>$42.00</strong></li>
<li>To: <a href="mailto:3labsio@gmail.com"><strong>3labsio@gmail.com</strong></a></li>
<li>Memo: <strong>Fieldproof</strong></li>
</ul>
<p><a href="${payUri}" id="fp-zelle-open" style="display:inline-block;background:#111;color:#fff;text-decoration:none;padding:.7rem 1.1rem;border-radius:999px;font-weight:600">Open $42 Zelle memo</a></p>
${copyPayControls('3labsio@gmail.com', '42.00', 'Copy email', 'Copy $42')}
${cardFallbackHtml()}
<script>
(function(){
  var PAY_URI = ${JSON.stringify(payUri)};
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText("3labsio@gmail.com").catch(function(){});
  }
  if (PAY_URI) location.replace(PAY_URI);
})();
</script>
</body></html>`;
      return new Response(html, { status: 200, headers: { 'content-type': 'text/html; charset=utf-8', Link: paymentLinkHeader(), ...corsHeaders() } });
    }

    if (request.method === 'GET' && (url.pathname === '/v1/pay/usdc.uri' || url.pathname === '/v1/pay/usdc.txt')) {
      const payTo = c.payTo || '0x07C2383008a9ed30581f27Db5531E19411c94fb3';
      return uriListResponse(usdcEip681(payTo));
    }

    if (request.method === 'GET' && (url.pathname === '/v1/pay/usdc.png' || url.pathname === '/v1/pay/usdc.qr')) {
      const payTo = c.payTo || '0x07C2383008a9ed30581f27Db5531E19411c94fb3';
      return Response.redirect(usdcQrUrl(payTo), 302);
    }

    if (request.method === 'GET' && url.pathname === '/v1/pay/usdc') {
      const payTo = c.payTo || '0x07C2383008a9ed30581f27Db5531E19411c94fb3';
      const payUri = usdcEip681(payTo);
      if (wantsUriList(request)) return uriListResponse(payUri);
      if (wantsJson(request)) {
        return json(
          200,
          {
            scheme: 'eip681',
            network: 'eip155:8453',
            asset: 'USDC',
            amountUsd: GOAL_USD,
            amountAtomic: '42000000',
            payTo,
            uri: payUri,
            qr: `https://api.qrserver.com/v1/create-qr-code/?size=240x240&data=${encodeURIComponent(payUri)}`,
            card: STRIPE_PAYMENT_LINK,
          },
          { Link: paymentLinkHeader() },
          true
        );
      }
      const qrUrl = `https://api.qrserver.com/v1/create-qr-code/?size=240x240&data=${encodeURIComponent(payUri)}`;
      const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Pay 42 USDC — Fieldproof</title>
<link rel="payment" href="${STRIPE_PAYMENT_LINK}">
</head><body style="font-family:system-ui,sans-serif;max-width:40rem;margin:2rem auto;padding:0 1rem;line-height:1.5;background:#f4efe6;color:#111">
<h1>Pay 42 USDC on Base</h1>
<p>One transfer of <strong>42 USDC</strong> on <strong>Base</strong>. Other networks may lose the funds. Scan the QR or pay in this browser.</p>
${walletPayControls(payTo, payUri)}
<p><a href="${payUri}">Open in wallet (EIP-681)</a></p>
<p><img src="${qrUrl}" width="240" height="240" alt="QR code for 42 USDC on Base"></p>
<p>Pay to:</p>
<pre style="white-space:pre-wrap;word-break:break-all">${payTo}</pre>
${copyPayControls(payTo, payUri)}
${cardFallbackHtml()}
<p>Token: USDC <code>0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913</code> · amount <code>42000000</code> atomic (6 decimals).</p>
</body></html>`;
      return new Response(html, { status: 200, headers: { 'content-type': 'text/html; charset=utf-8', Link: paymentLinkHeader(), ...corsHeaders() } });
    }

    if (request.method === 'GET' && url.pathname === '/v1/checkouts') {
      let btc = null;
      try { btc = await observeBtc(); } catch { btc = null; }
      if (wantsHtml(request)) {
        return new Response(payIndexHtml(url.origin, btc), {
          status: 200,
          headers: { 'content-type': 'text/html; charset=utf-8', Link: paymentLinkHeader(), ...corsHeaders() },
        });
      }
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
      if (wantsHtml(request)) return htmlCheckoutResponse(url.origin);
      return json(200, agentCard(url.origin), { Link: paymentLinkHeader() }, true);
    }

    if (request.method === 'GET' && url.pathname === '/.well-known/ai-plugin.json') {
      if (wantsHtml(request)) return htmlCheckoutResponse(url.origin);
      return json(200, aiPluginManifest(url.origin), { Link: paymentLinkHeader() }, true);
    }

    if (request.method === 'GET' && url.pathname === '/.well-known/mcp.json') {
      if (wantsHtml(request)) return htmlCheckoutResponse(url.origin);
      return json(200, mcpDiscovery(url.origin), { Link: paymentLinkHeader() }, true);
    }

    if (request.method === 'GET' && url.pathname === '/.well-known/nodeinfo') {
      if (wantsHtml(request)) return htmlCheckoutResponse(url.origin);
      return json(200, nodeInfoIndex(url.origin), { Link: paymentLinkHeader() }, true);
    }

    if (request.method === 'GET' && (url.pathname === '/nodeinfo/2.1' || url.pathname === '/.well-known/nodeinfo/2.1')) {
      if (wantsHtml(request)) return htmlCheckoutResponse(url.origin);
      return json(200, nodeInfo21(url.origin), { Link: paymentLinkHeader() }, true);
    }

    if (request.method === 'GET' && url.pathname === '/.well-known/webfinger') {
      if (wantsHtml(request)) return htmlCheckoutResponse(url.origin);
      const resource = url.searchParams.get('resource');
      if (!resource) {
        return json(400, { error: 'resource_required', example: `${url.origin}/.well-known/webfinger?resource=acct:pay@${url.host}` }, { Link: paymentLinkHeader() }, true);
      }
      if (!webfingerKnown(url.origin, resource)) {
        return json(404, { error: 'unknown_resource', resource }, { Link: paymentLinkHeader() }, true);
      }
      return new Response(JSON.stringify(webfingerJrd(url.origin, resource), null, 2), {
        status: 200,
        headers: {
          'content-type': 'application/jrd+json; charset=utf-8',
          Link: paymentLinkHeader(),
          ...corsHeaders(),
        },
      });
    }

    if (request.method === 'GET' && (url.pathname === '/.well-known/host-meta' || url.pathname === '/.well-known/host-meta.xml')) {
      if (wantsHtml(request)) return htmlCheckoutResponse(url.origin);
      return new Response(hostMetaXml(url.origin), {
        status: 200,
        headers: {
          'content-type': 'application/xrd+xml; charset=utf-8',
          Link: paymentLinkHeader(),
          ...corsHeaders(),
        },
      });
    }

    if (request.method === 'GET' && url.pathname === '/.well-known/host-meta.json') {
      if (wantsHtml(request)) return htmlCheckoutResponse(url.origin);
      return new Response(JSON.stringify(hostMetaJson(url.origin), null, 2), {
        status: 200,
        headers: {
          'content-type': 'application/jrd+json; charset=utf-8',
          Link: paymentLinkHeader(),
          ...corsHeaders(),
        },
      });
    }

    if (request.method === 'GET' && (url.pathname === '/.well-known/did.json' || url.pathname === '/did.json')) {
      if (wantsHtml(request)) return htmlCheckoutResponse(url.origin);
      return new Response(JSON.stringify(didWeb(url.origin), null, 2), {
        status: 200,
        headers: {
          'content-type': 'application/did+json; charset=utf-8',
          Link: paymentLinkHeader(),
          ...corsHeaders(),
        },
      });
    }

    if (
      request.method === 'GET' &&
      (url.pathname === '/humans.txt' || url.pathname === '/.well-known/humans.txt')
    ) {
      if (url.pathname === '/humans.txt' && wantsHtml(request)) {
        let btc = null;
        try { btc = await observeBtc(); } catch { btc = null; }
        return new Response(payIndexHtml(url.origin, btc), {
          status: 200,
          headers: { 'content-type': 'text/html; charset=utf-8', Link: paymentLinkHeader(), ...corsHeaders() },
        });
      }
      return new Response(humansTxt(url.origin), {
        status: 200,
        headers: {
          'content-type': 'text/plain; charset=utf-8',
          Link: paymentLinkHeader(),
          ...corsHeaders(),
        },
      });
    }

    if (
      request.method === 'GET' &&
      (url.pathname === '/.well-known/security.txt' || url.pathname === '/security.txt')
    ) {
      if (url.pathname === '/security.txt' && wantsHtml(request)) {
        let btc = null;
        try { btc = await observeBtc(); } catch { btc = null; }
        return new Response(payIndexHtml(url.origin, btc), {
          status: 200,
          headers: { 'content-type': 'text/html; charset=utf-8', Link: paymentLinkHeader(), ...corsHeaders() },
        });
      }
      return new Response(securityTxt(url.origin), {
        status: 200,
        headers: {
          'content-type': 'text/plain; charset=utf-8',
          Link: paymentLinkHeader(),
          ...corsHeaders(),
        },
      });
    }

    if (
      request.method === 'GET' &&
      (url.pathname === '/skills/pay/SKILL.md' ||
        url.pathname === '/skills/pay' ||
        url.pathname === '/skills/pay/' ||
        url.pathname === '/.well-known/skills/pay/SKILL.md')
    ) {
      if (url.pathname !== '/.well-known/skills/pay/SKILL.md' && wantsHtml(request)) {
        let btc = null;
        try { btc = await observeBtc(); } catch { btc = null; }
        return new Response(payIndexHtml(url.origin, btc), {
          status: 200,
          headers: { 'content-type': 'text/html; charset=utf-8', Link: paymentLinkHeader(), ...corsHeaders() },
        });
      }
      return new Response(skillPayMd(url.origin), {
        status: 200,
        headers: {
          'content-type': 'text/markdown; charset=utf-8',
          Link: paymentLinkHeader(),
          ...corsHeaders(),
        },
      });
    }

    if (request.method === 'GET' && (url.pathname === '/.well-known/skills.json' || url.pathname === '/skills.json')) {
      if (url.pathname === '/skills.json' && wantsHtml(request)) {
        let btc = null;
        try { btc = await observeBtc(); } catch { btc = null; }
        return new Response(payIndexHtml(url.origin, btc), {
          status: 200,
          headers: { 'content-type': 'text/html; charset=utf-8', Link: paymentLinkHeader(), ...corsHeaders() },
        });
      }
      return json(200, skillsIndex(url.origin), { Link: paymentLinkHeader() }, true);
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
      if (url.pathname !== '/.well-known/pay.json' && wantsHtml(request)) {
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
          name: 'Fieldproof',
          price_usd: 42,
          currency: 'USD',
          url: STRIPE_PAYMENT_LINK,
          short_url: `${url.origin}/pay`,
          methods: ['card', 'cashapp', 'link', 'us_bank_account', 'klarna', 'afterpay_clearpay', 'affirm'],
          also: {
            invoice: `${url.origin}/v1/invoice`,
            quote: `${url.origin}/v1/quote`,
            skill: `${url.origin}/skills/pay/SKILL.md`,
            funding: `${url.origin}/package.json`,
            card_uri: `${url.origin}/v1/pay/card.uri`,
            card_qr: `${url.origin}/v1/pay/card.png`,
            usdc: `${url.origin}/v1/pay/usdc`,
            usdc_uri: `${url.origin}/v1/pay/usdc.uri`,
            usdc_qr: `${url.origin}/v1/pay/usdc.png`,
            btc: `${url.origin}/v1/pay/btc`,
            btc_uri: `${url.origin}/v1/pay/btc.uri`,
            btc_qr: `${url.origin}/v1/pay/btc.png`,
            scan: `${url.origin}/v1/pay/scan`,
            zelle: `${url.origin}/v1/pay/zelle`,
            zelle_uri: `${url.origin}/v1/pay/zelle.uri`,
            zelle_qr: `${url.origin}/v1/pay/zelle.png`,
            store: 'https://store.3labs.io',
            pack_uri: `${url.origin}/v1/pay/pack.uri`,
            tip_uri: `${url.origin}/v1/pay/tip-jar.uri`,
            security: `${url.origin}/.well-known/security.txt`,
            humans: `${url.origin}/humans.txt`,
            webfinger: `${url.origin}/.well-known/webfinger?resource=acct:pay@${new URL(url.origin).host}`,
            nodeinfo: `${url.origin}/.well-known/nodeinfo`,
            host_meta: `${url.origin}/.well-known/host-meta.json`,
            did: `${url.origin}/.well-known/did.json`,
          },
        },
        {},
        true
      );
    }

    if (request.method === 'GET' && url.pathname === '/.well-known/x402') {
      if (wantsHtml(request)) {
        let btc = null;
        try { btc = await observeBtc(); } catch { btc = null; }
        return new Response(payIndexHtml(url.origin, btc), {
          status: 200,
          headers: { 'content-type': 'text/html; charset=utf-8', Link: paymentLinkHeader(), ...corsHeaders() },
        });
      }
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
      if (wantsHtml(request)) {
        const payTo = c.payTo || '0x07C2383008a9ed30581f27Db5531E19411c94fb3';
        const payUri = usdcEip681(payTo);
        const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Pay $42 — Policy Gate check</title>
<link rel="payment" href="${STRIPE_PAYMENT_LINK}">
</head><body style="font-family:system-ui,sans-serif;max-width:44rem;margin:2rem auto;padding:0 1rem;line-height:1.5;background:#f4efe6;color:#111">
<h1>POST /v1/check</h1>
<p>This page stays here so you can pick a rail. POST without payment still returns 402. Card checkout delivers the Ethics Check and C-suite Word ZIPs, not the Governance Pack.</p>
<p><a href="${STRIPE_PAYMENT_LINK}" style="display:inline-block;background:#111;color:#fff;text-decoration:none;padding:.7rem 1.1rem;border-radius:999px;font-weight:600">Pay $42 with card</a></p>
${walletPayControls(payTo, payUri)}
<p>Agents: <code>POST /v1/check</code> with a policy and request. Free evaluation: <a href="/v1/example">GET /v1/example</a>. Pack: <a href="${GUMROAD_PACK}">Buy the $42 pack</a>. Scan: <a href="${url.origin}/v1/pay/scan">USDC / BTC / Zelle</a>.</p>
</body></html>`;
        return new Response(html, {
          status: 200,
          headers: { 'content-type': 'text/html; charset=utf-8', Link: paymentLinkHeader(), ...corsHeaders() },
        });
      }
      return json(
        200,
        {
          endpoint: `${url.origin}/v1/check`,
          method: 'POST',
          paid: !c.free,
          usage: 'POST { "policy_id": "default-action-tiers" | "policy": {...}, "request": { "action": "...", "params": {...} }, "ledger"?: { "committed_usd": 0, "intended_usd": 0 } }',
          ledger: {
            what: 'Optional cumulative exposure for the window. A per-action gate cannot see repetition: 49 payments of $40 each pass a $50 rule individually.',
            fields: 'committed_<field> plus intended_<field>, summed. intended counts so a burst still in flight is not invisible to the cap bounding it.',
            fails_closed: 'If a policy declares a cumulative condition and no ledger is sent, the verdict is deny with ledger_required: true. Explicit zeros are an answer; an omitted ledger is not.',
            unresolved: 'unknown_<field> greater than zero means an effect was dispatched and never resolved. Any outstanding unknown denies with unresolved_intent: true, regardless of headroom, because the system has lost track of that quantity. It closes by observing the target, never by a clock.',
          },
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
      if (wantsHtml(request)) {
        const titles = CANONS.map((c) => `<li><strong>${c.id}</strong> — ${c.title}</li>`).join('');
        const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Pay $42 — Fieldproof canons</title>
<link rel="payment" href="${STRIPE_PAYMENT_LINK}">
</head><body style="font-family:system-ui,sans-serif;max-width:44rem;margin:2rem auto;padding:0 1rem;line-height:1.5;background:#f4efe6;color:#111">
<h1>Seven canons</h1>
<p>This page stays here so you can read the canons, then pick a rail. The canons are free. The Ethics Check Word kit is $42 and downloads after card checkout.</p>
<p><a href="${STRIPE_ETHICS_LINK}" style="display:inline-block;background:#111;color:#fff;text-decoration:none;padding:.7rem 1.1rem;border-radius:999px;font-weight:600">Pay $42 for the Ethics Check kit</a> <a href="${STRIPE_PAYMENT_LINK}">Pay $42 with card</a></p>
<ul>${titles}</ul>
<p>After payment: <a href="${ETHICS_ZIP}">Fieldproof-Ethics-Check-Launch-Kit.zip</a>. JSON: <a href="/v1/canons">GET /v1/canons</a> without HTML Accept. Pack: <a href="${GUMROAD_PACK}">Buy the $42 pack</a>. Scan: <a href="${url.origin}/v1/pay/scan">USDC / BTC / Zelle</a>.</p>
</body></html>`;
        return new Response(html, {
          status: 200,
          headers: { 'content-type': 'text/html; charset=utf-8', Link: paymentLinkHeader(), ...corsHeaders() },
        });
      }
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
      if (wantsHtml(request)) {
        const payTo = c.payTo || '0x07C2383008a9ed30581f27Db5531E19411c94fb3';
        const payUri = usdcEip681(payTo);
        const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Pay $42 — ethics check</title>
<link rel="payment" href="${STRIPE_PAYMENT_LINK}">
</head><body style="font-family:system-ui,sans-serif;max-width:44rem;margin:2rem auto;padding:0 1rem;line-height:1.5;background:#f4efe6;color:#111">
<h1>Ethics Check</h1>
<p>This page stays here so you can pick a rail. The Ethics Check Word kit is $42. POST /v1/ethics-check is a separate $0.01 x402 screen.</p>
<p><a href="${STRIPE_ETHICS_LINK}" style="display:inline-block;background:#111;color:#fff;text-decoration:none;padding:.7rem 1.1rem;border-radius:999px;font-weight:600">Pay $42 for the Ethics Check kit</a> <a href="${STRIPE_PAYMENT_LINK}">Pay $42 with card</a></p>
${walletPayControls(payTo, payUri)}
<p>After payment: <a href="${ETHICS_ZIP}">Fieldproof-Ethics-Check-Launch-Kit.zip</a>. Free canons: <a href="/v1/canons">GET /v1/canons</a>. Pack: <a href="${GUMROAD_PACK}">Buy the $42 pack</a>. Scan: <a href="${url.origin}/v1/pay/scan">USDC / BTC / Zelle</a>.</p>
</body></html>`;
        return new Response(html, {
          status: 200,
          headers: { 'content-type': 'text/html; charset=utf-8', Link: paymentLinkHeader(), ...corsHeaders() },
        });
      }
      const priced = pricedCfg(c, ETHICS_PRICE_USD, 'Screen a declared action against the seven canons');
      // A paid endpoint whose docs omit the request shape is a paywall in front of a guess.
      // This one shipped with no `usage` at all: price, but no way to know what to send.
      return json(200, {
        endpoint: `${url.origin}/v1/ethics-check`,
        method: 'POST',
        price_usd: ETHICS_PRICE_USD,
        canons: `${url.origin}/v1/canons`,
        usage: `POST ${url.origin}/v1/ethics-check with { "action": "...", "summary"?: "...", "declared"?: { ... } }`,
        what_it_does:
          'Screens a DECLARED action against seven canons and returns clear | reflect | stop, with the canons ' +
          'that fired and why. Deterministic, no model in the path. It answers "should I?" — the Policy Gate at ' +
          '/v1/check answers "am I allowed to?", and they are different questions.',
        declared_fields: {
          deception: 'boolean — does the act depend on someone believing something untrue',
          disclosure: 'boolean — would you do it if it were published',
          affects_others: 'boolean — are other beings affected',
          consent: 'boolean — have those beings agreed',
          reversible: 'boolean — can the act be undone',
          impact_usd: 'number — magnitude of the effect',
          data_sensitivity: 'string — e.g. none | internal | personal',
        },
        example_request: {
          action: 'messages.send',
          summary: 'Email 400 customers about a pricing change',
          declared: { deception: false, disclosure: true, affects_others: true, consent: false, reversible: false, impact_usd: 0 },
        },
        limitation:
          'It screens the DECLARATION, not the world. It cannot see what you do not declare, and an undeclared ' +
          'field is returned as a question rather than passing silently. A screening tool that oversells its ' +
          'coverage commits the failure its own first canon names.',
        free_first: `${url.origin}/v1/canons`,
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
      if (wantsHtml(request)) {
        const ids = Object.keys(BUILTINS).map((id) => `<li><code>${id}</code></li>`).join('');
        const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Pay $42 — Fieldproof policies</title>
<link rel="payment" href="${STRIPE_PAYMENT_LINK}">
</head><body style="font-family:system-ui,sans-serif;max-width:44rem;margin:2rem auto;padding:0 1rem;line-height:1.5;background:#f4efe6;color:#111">
<h1>Policies are public</h1>
<p>This page stays here so you can read the ruleset, then pick a rail. Card checkout delivers the Ethics Check and C-suite Word ZIPs, not the Governance Pack.</p>
<p><a href="${STRIPE_PAYMENT_LINK}" style="display:inline-block;background:#111;color:#fff;text-decoration:none;padding:.7rem 1.1rem;border-radius:999px;font-weight:600">Pay $42 with card</a></p>
<ul>${ids}</ul>
<p>JSON: <a href="/v1/policies">GET /v1/policies</a> without HTML Accept. Worked verdicts: <a href="/v1/example">GET /v1/example</a>. Pack: <a href="${GUMROAD_PACK}">Buy the $42 pack</a>. Scan: <a href="${url.origin}/v1/pay/scan">USDC / BTC / Zelle</a>.</p>
</body></html>`;
        return new Response(html, {
          status: 200,
          headers: { 'content-type': 'text/html; charset=utf-8', Link: paymentLinkHeader(), ...corsHeaders() },
        });
      }
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
      if (wantsHtml(request)) {
        const rows = samples
          .map((s) => {
            const v = check(DEFAULT_POLICY, s.request);
            return `<li>${s.label}: <strong>${v.decision}</strong></li>`;
          })
          .join('');
        const html = `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Pay $42 — Fieldproof examples</title>
<link rel="payment" href="${STRIPE_PAYMENT_LINK}">
</head><body style="font-family:system-ui,sans-serif;max-width:44rem;margin:2rem auto;padding:0 1rem;line-height:1.5;background:#f4efe6;color:#111">
<h1>Worked verdicts</h1>
<p>This page stays here so you can judge the engine, then pick a rail. Verdicts below are live from the same engine as POST /v1/check. Card checkout delivers the Ethics Check and C-suite Word ZIPs, not the Governance Pack.</p>
<p><a href="${STRIPE_PAYMENT_LINK}" style="display:inline-block;background:#111;color:#fff;text-decoration:none;padding:.7rem 1.1rem;border-radius:999px;font-weight:600">Pay $42 with card</a></p>
<ul>${rows}</ul>
<p>JSON: <a href="/v1/example">GET /v1/example</a> without HTML Accept. Pack: <a href="${GUMROAD_PACK}">Buy the $42 pack</a>. Scan: <a href="${url.origin}/v1/pay/scan">USDC / BTC / Zelle</a>.</p>
</body></html>`;
        return new Response(html, {
          status: 200,
          headers: { 'content-type': 'text/html; charset=utf-8', Link: paymentLinkHeader(), ...corsHeaders() },
        });
      }
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
          // The failure a per-action gate cannot see, demonstrated rather than asserted.
          // 49 payments of $40 each pass a "$50 needs approval" rule individually; the
          // aggregate is a $1,960 incident and every line of the log is defensible.
          cumulative_exposure: (() => {
            const capped = {
              version: '1.0',
              name: 'spend-cap-example',
              default: 'deny',
              tiers: {
                2: { decision: 'require_approval', label: 'hard to reverse' },
                3: { decision: 'deny', label: 'forbidden for agents' },
              },
              rules: [
                {
                  id: 'daily-spend-cap',
                  match: { action: 'payments.*', cumulative: [{ field: 'usd', gt: 500 }] },
                  tier: 3,
                  rationale: 'Cumulative spend in the window is over the cap.',
                },
                { id: 'small-payments-ok', match: { action: 'payments.*' }, tier: 2 },
              ],
            };
            const req = { action: 'payments.send', params: { amount_usd: 40 } };
            const shown = (ledger) => {
              const v = check(capped, req, ledger);
              return {
                ledger: ledger ?? null,
                decision: v.decision,
                matched_rule: v.matched_rule,
                ledger_required: v.ledger_required ?? false,
                unresolved_intent: v.unresolved_intent ?? false,
              };
            };
            return {
              why: 'The same $40 payment, four times. Only the history changes.',
              policy: capped,
              request: req,
              cases: [
                shown({ committed_usd: 300, intended_usd: 0 }),
                shown({ committed_usd: 1960, intended_usd: 0 }),
                shown({ committed_usd: 400, intended_usd: 150 }),
                shown({ committed_usd: 20, intended_usd: 0, unknown_usd: 5 }),
                shown(undefined),
              ],
              notes: {
                intended_counts: 'intended is summed with committed, so a burst still in flight is not invisible to the cap meant to bound it.',
                fails_closed: 'No ledger returns deny with ledger_required. A cap you can skip by omitting state is decorative. Explicit zeros are an answer; an omitted ledger is not.',
                still_deterministic: 'Same policy, same request, same ledger, same verdict. History is an input, not a source of nondeterminism.',
                credit: 'This gap was found in public by Moltbook agents neo_konsi_s2bw and maies, arguing with us about retry loops.',
              },
            };
          })(),
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

    if (request.method === 'GET' && (url.pathname === '/v1/invoice' || url.pathname === '/v1/invoice/' || url.pathname === '/.well-known/invoice.json')) {
      const payTo = c.payTo || '0x07C2383008a9ed30581f27Db5531E19411c94fb3';
      let btc = null;
      try { btc = await observeBtc(); } catch { btc = null; }
      const invoice = fieldproofInvoice(url.origin, payTo, btc);
      if (wantsUriList(request)) {
        const lines = [STRIPE_PAYMENT_LINK, invoice.methods.find((m) => m.scheme === 'eip681')?.uri, invoice.methods.find((m) => m.scheme === 'bip21')?.uri, invoice.methods.find((m) => m.scheme === 'zelle')?.uri].filter(Boolean);
        return uriListResponse(lines.join('\n'));
      }
      if (url.pathname !== '/.well-known/invoice.json' && wantsHtml(request)) {
        return new Response(invoiceHtml(url.origin, payTo, btc), {
          status: 200,
          headers: { 'content-type': 'text/html; charset=utf-8', Link: paymentLinkHeader(), ...corsHeaders() },
        });
      }
      return json(200, invoice, { Link: paymentLinkHeader() }, true);
    }

    if (
      (request.method === 'GET' || request.method === 'POST') &&
      (url.pathname === '/v1/offer' ||
        url.pathname === '/v1/offer/' ||
        url.pathname === '/v1/quote' ||
        url.pathname === '/v1/quote/')
    ) {
      if (request.method === 'GET' && wantsHtml(request)) {
        let btc = null;
        try { btc = await observeBtc(); } catch { btc = null; }
        return new Response(payIndexHtml(url.origin, btc), {
          status: 200,
          headers: { 'content-type': 'text/html; charset=utf-8', Link: paymentLinkHeader(), ...corsHeaders() },
        });
      }
      const quote = sponsorCfg(c);
      if (c.free) {
        return json(
          200,
          { price_usd: 42, card: STRIPE_PAYMENT_LINK, fallback: stripeFallbackOffer(), method: request.method },
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
      // 200 docs carrying `accepts`, NOT a 402. This is our own playbook's defect 3: a 402 on
      // GET passes a directory's one-off verification and then fails its recurring health
      // probe, so the listing goes quiet while the service is fine. Every other paid route
      // here already returns 200 on GET; this one — the only endpoint whose single use meets
      // the $42 bar — was the exception.
      return json(200, {
        endpoint: `${url.origin}/v1/sponsor`,
        method: 'POST',
        paid: true,
        price_usd: 42,
        amount_atomic: quote.amount,
        asset: 'USDC',
        network: 'Base (eip155:8453)',
        pay_to: payTo,
        what_it_is:
          'One 42 USDC settlement that meets this business\'s first-$42 external-income bar in a single payment. ' +
          'Self-payments are excluded from that counter and the $0.005 smoke test does not count.',
        usage: `POST ${url.origin}/v1/sponsor with an x402 payment of ${quote.amount} atomic USDC. Unpaid POST returns the 402 challenge.`,
        free_first: {
          worked_verdicts: `${url.origin}/v1/example`,
          full_ruleset: `${url.origin}/v1/policies`,
          note: 'Nothing about how a verdict is reached sits behind the paywall. Evaluate before paying.',
        },
        accepts: [paymentRequirementsV1(quote, `${url.origin}/v1/sponsor`)],
        fallback: stripeFallbackOffer(),
        card: STRIPE_PAYMENT_LINK,
      }, { Link: paymentLinkHeader() });
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
