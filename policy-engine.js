/**
 * Fieldproof Policy Gate — deterministic policy engine v0.2
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
 *    2 hard-to-reverse (raise a live gate), 3 forbidden.
 *  - Opaque-secret connectors: the engine may allow vault/connector *use*
 *    while denying secret *exposure*. Fail closed on missing authorization,
 *    expired approval, scope mismatch, connector failure, missing diff,
 *    failed verification, revocation, or emergency-disable.
 *  - Recorded overrides can relax default rules except hard denials
 *    (secret-in-request, secret exposure, revoked connector, emergency-disable).
 */

'use strict';

const DECISIONS = new Set(['allow', 'require_approval', 'deny']);

const SECRET_SHAPE = /(sk-[A-Za-z0-9_-]{12,}|-----BEGIN [A-Z ]+PRIVATE KEY-----|password\s*[:=]|api[_-]?key\s*[:=]\s*["'][^"']+)/i;
const SECRET_KEYS = new Set([
  'password', 'secret', 'token', 'apikey', 'api_key', 'masterkey', 'master_key',
  'privatekey', 'private_key', 'credential', 'passphrase', 'unlock',
]);
const HARD_DENY = new Set([
  'secret_in_request',
  'secret_exposure',
  'connector_revoked',
  'emergency_disable',
]);
const MUTATING_ACTIONS = /^(dns\.write|website\.(create|update)|vault\.opaque\.write|secret\.set|connector\.invoke|deploy\.|repo\.create|social\.post)/;
const MAILGUN_HINT = /\b(mx|spf|dkim)\b/i;

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

function containsSecret(value) {
  if (value == null) return false;
  if (typeof value === 'string') return SECRET_SHAPE.test(value);
  if (Array.isArray(value)) return value.some(containsSecret);
  if (typeof value === 'object') {
    for (const [key, child] of Object.entries(value)) {
      if (SECRET_KEYS.has(String(key).toLowerCase()) && child != null && child !== '') return true;
      if (containsSecret(child)) return true;
    }
  }
  return false;
}

function redact(value) {
  if (value == null || typeof value !== 'object') return value;
  const out = Array.isArray(value) ? [] : {};
  for (const [key, child] of Object.entries(value)) {
    if (SECRET_KEYS.has(String(key).toLowerCase())) continue;
    if (typeof child === 'string' && SECRET_SHAPE.test(child)) continue;
    out[key] = typeof child === 'object' ? redact(child) : child;
  }
  return out;
}

function scopeAllows(scope, target) {
  if (target == null || target === '') return true;
  const allowed = Array.isArray(scope) ? scope : [scope];
  return allowed.some((item) => item === target || (typeof item === 'string' && typeof target === 'string' && (target === item || target.endsWith('.' + item))));
}

function isMutating(action, capability) {
  if (capability === 'dns-write' || capability === 'website-create-update') return true;
  return MUTATING_ACTIONS.test(action || '');
}

function buildReceipt(request, decision, reason, extra) {
  const connector = request.connector || {};
  const approval = request.approval || connector.approval || {};
  return redact({
    action: request.action || null,
    decision,
    reason,
    connectorId: connector.id || request.connectorId || null,
    ref: connector.ref || request.ref || null,
    capability: request.capability || connector.capability || null,
    scope: request.scope || connector.scopes || null,
    target: request.target || connector.target || null,
    approver: approval.approvedBy || approval.approver || connector.approver || null,
    expiresAt: approval.expiresAt || connector.ttl || null,
    revoked: Boolean(approval.revoked || connector.revoked || connector.emergencyDisable),
    idempotencyKey: request.idempotencyKey || connector.idempotencyKey || null,
    verified: request.verification && Object.prototype.hasOwnProperty.call(request.verification, 'ok')
      ? request.verification.ok
      : (connector.verification && Object.prototype.hasOwnProperty.call(connector.verification, 'ok') ? connector.verification.ok : null),
    redacted: true,
    ...(extra || {}),
  });
}

function verdict(base, request, extraReceipt) {
  const receipt = buildReceipt(request, base.decision, base.rationale || base.reason, extraReceipt);
  return { ...base, receipt, raise_gate: base.decision === 'require_approval' };
}

function connectorFailure(request, reason) {
  return verdict({
    decision: 'deny',
    matched_rule: 'connector-gate',
    tier: 3,
    tier_label: 'forbidden for agents',
    rationale: reason,
    policy_version: null,
    default_applied: false,
    reason,
  }, request);
}

function matchOverride(overrides, request, now) {
  return (overrides || []).find((item) => {
    if (!item || item.revoked) return false;
    if (item.expiresAt && Date.parse(item.expiresAt) <= now) return false;
    if (item.action && !globMatch(item.action, request.action || '')) return false;
    if (item.target && item.target !== request.target) return false;
    return DECISIONS.has(item.decision);
  }) || null;
}

function applyOverride(policy, request, now, hardReason) {
  if (HARD_DENY.has(hardReason)) return null;
  const override = matchOverride(policy.overrides, request, now);
  if (!override) return null;
  return verdict({
    decision: override.decision,
    matched_rule: 'policy-override',
    tier: override.decision === 'allow' ? 1 : override.decision === 'require_approval' ? 2 : 3,
    tier_label: override.decision === 'allow' ? 'override allow' : override.decision === 'require_approval' ? 'override raise gate' : 'override deny',
    rationale: `Recorded override "${override.id}"`,
    policy_version: policy.version || null,
    default_applied: false,
    override_id: override.id,
  }, request, { overrideId: override.id });
}

function connectorGate(policy, request, now) {
  if (containsSecret(request)) return connectorFailure(request, 'secret_in_request');

  const action = request.action || '';
  if (/^(vault\.opaque\.read|secret\.expose|auth\.browser)/.test(action)) {
    return connectorFailure(request, 'secret_exposure');
  }

  const connector = request.connector;
  if (!connector && !request.approval && !isMutating(action, request.capability)) return null;

  if (connector) {
    if (connector.emergencyDisable === true) return connectorFailure(request, 'emergency_disable');
    if (connector.revoked === true) return connectorFailure(request, 'connector_revoked');
    if ((connector.available === false || connector.health === 'unavailable') && (isMutating(action, request.capability) || action === 'connector.invoke')) {
      const denied = connectorFailure(request, 'connector_unavailable');
      denied.tier = 1;
      return denied;
    }
    const needed = request.capability;
    const caps = connector.capabilities || [];
    const capList = Array.isArray(caps)
      ? caps
      : [...(caps.read || []), ...(caps.mutateDns || []), ...(caps.mutateWebsite || [])];
    if (needed && capList.length && !capList.includes(needed)) {
      return connectorFailure(request, 'capability_mismatch');
    }
    const scope = request.scope || connector.scopes;
    const target = request.target || connector.target;
    if (target && scope && !scopeAllows(scope, target)) {
      return connectorFailure(request, 'scope_mismatch');
    }
    if (action === 'dns.write' && request.capability === 'website-create-update') {
      return connectorFailure(request, 'capability_mismatch');
    }
    if ((action === 'website.update' || action === 'website.create') && request.capability === 'dns-write') {
      return connectorFailure(request, 'capability_mismatch');
    }
  }

  if (isMutating(action, request.capability)) {
    const approval = request.approval || connector?.approval || {};
    const standing = Boolean(connector?.standing_grant || approval.standing_grant || request.standing_grant);
    const named = approval.name || approval.approvedBy || connector?.approver;
    if (!standing && !named) {
      return applyOverride(policy, request, now, 'missing_authorization') || connectorFailure(request, 'missing_authorization');
    }
    if (approval.revoked === true) return connectorFailure(request, 'approval_revoked');
    const expiresAt = approval.expiresAt || (typeof connector?.ttl === 'string' ? connector.ttl : null);
    if (expiresAt && Date.parse(expiresAt) <= now) {
      return applyOverride(policy, request, now, 'approval_expired') || connectorFailure(request, 'approval_expired');
    }
    if (!request.diff && !connector?.diff) return connectorFailure(request, 'missing_diff');
    if (!request.idempotencyKey && !connector?.idempotencyKey) {
      return connectorFailure(request, 'missing_idempotency_key');
    }
    if (request.verification && request.verification.ok === false) {
      return connectorFailure(request, 'verification_failed');
    }
  }

  const target = request.target || connector?.target || '';
  const mailText = `${typeof request.diff === 'string' ? request.diff : JSON.stringify(request.diff || {})} ${JSON.stringify(request.records || [])}`;
  if ((action === 'dns.write' || request.capability === 'dns-write') && (target === '3labs.io' || String(target).endsWith('.3labs.io')) && MAILGUN_HINT.test(mailText) && !request.mailChangeApproved) {
    return connectorFailure(request, 'mailgun_protected');
  }

  return null;
}

/**
 * check(policy, request) -> verdict
 * request: { action: "payments.send", actor?: "agent-id", params?: {...},
 *            connector?, approval?, capability?, target?, scope?, diff?,
 *            idempotencyKey?, verification? }
 */
function check(policy, request) {
  const errors = validatePolicy(policy);
  if (errors.length) return { error: 'invalid_policy', details: errors };
  if (!request || typeof request.action !== 'string' || !request.action.length) {
    return { error: 'invalid_request', details: ['request.action (string) is required'] };
  }

  const now = request.now || Date.now();
  const gated = connectorGate(policy, request, now);
  if (gated) return gated;

  const overrideHit = applyOverride(policy, request, now, null);
  if (overrideHit && overrideHit.decision !== 'deny') return overrideHit;

  const rules = policy.rules || [];
  for (const rule of rules) {
    if (!ruleMatches(rule, request)) continue;
    const tier = rule.tier !== undefined ? String(rule.tier) : null;
    const decision = tier !== null ? policy.tiers[tier].decision : rule.decision;
    return verdict({
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
    }, request);
  }

  if (overrideHit) return overrideHit;

  const def = policy.default || 'deny';
  return verdict({
    decision: def,
    matched_rule: null,
    tier: null,
    tier_label: null,
    rationale: `No rule matched; policy default is "${def}".`,
    policy_version: policy.version || null,
    default_applied: true,
  }, request);
}

module.exports = { check, validatePolicy, globMatch, containsSecret, redact, buildReceipt };
