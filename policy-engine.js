/**
 * Fieldproof Policy Gate — deterministic policy engine v0.1
 * Zero dependencies. Node >= 18.
 *
 * Evaluates a proposed agent action against a machine-readable policy and
 * returns a verdict: "allow" | "require_approval" | "deny".
 *
 * Design goals:
 *  - Deterministic: same input -> same output, always. No LLM in the hot path,
 *    so marginal cost per check is ~zero and results are auditable.
 *  - First-match-wins rule order, default-deny (configurable).
 *  - Action tiers (0..3) as the core abstraction, mirroring the Fieldproof
 *    Agentic AI Governance Pack: 0 read-only, 1 reversible write,
 *    2 hard-to-reverse (human approval), 3 forbidden.
 */

'use strict';

const DECISIONS = new Set(['allow', 'require_approval', 'deny']);

/** Glob match: '*' matches within a segment, '**' matches across segments. */
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

/** Evaluate one condition object against action params/context. */
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

/**
 * check(policy, request) -> verdict
 * request: { action: "payments.send", actor?: "agent-id", params?: {...} }
 */
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

module.exports = { check, validatePolicy, globMatch };
