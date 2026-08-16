'use strict';
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const { check, globMatch, containsSecret, redact, buildReceipt } = require('./policy-engine.js');

const policy = JSON.parse(
  fs.readFileSync(path.join(__dirname, 'policies', 'default-action-tiers.json'), 'utf8')
);

const cases = [
  // [request, expected decision, expected rule]
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
  [{ action: 'something.unheard.of' }, 'deny', null], // default-deny
];

let pass = 0;
for (const [req, wantDecision, wantRule] of cases) {
  const v = check(policy, req);
  assert.strictEqual(v.decision, wantDecision, `${req.action}: got ${v.decision}, want ${wantDecision}`);
  assert.strictEqual(v.matched_rule, wantRule, `${req.action}: matched ${v.matched_rule}, want ${wantRule}`);
  pass++;
}

// Engine hygiene
assert.ok(globMatch('*.read', 'a.read') && !globMatch('*.read', 'a.b.read'), 'single-star scoping');
assert.ok(globMatch('**.delete', 'a.b.delete'), 'double-star spans segments');
assert.strictEqual(check(policy, { action: '' }).error, 'invalid_request');
assert.strictEqual(check({ default: 'nope' }, { action: 'x' }).error, 'invalid_policy');
// Determinism: same input twice -> identical output
const a = JSON.stringify(check(policy, { action: 'payments.send', params: { amount_usd: 25 } }));
const b = JSON.stringify(check(policy, { action: 'payments.send', params: { amount_usd: 25 } }));
assert.strictEqual(a, b, 'deterministic');

const planted = "api_key='not-a-real-secret-but-shaped'";
assert.equal(containsSecret({ note: planted }), true);
assert.equal(containsSecret({ password: 'x' }), true);
assert.equal(JSON.stringify(redact({ password: 'x', ref: 'keepass:fieldproof' })).includes('password'), false);
assert.doesNotMatch(JSON.stringify(redact({ note: planted, ref: 'keepass:fieldproof' })), /api_key=/);

const secretInRequest = check(policy, { action: 'vault.opaque.use', params: { note: planted } });
assert.equal(secretInRequest.decision, 'deny');
assert.equal(secretInRequest.reason, 'secret_in_request');
assert.doesNotMatch(JSON.stringify(secretInRequest), /api_key=/);

const secretRead = check(policy, { action: 'vault.opaque.read' });
assert.equal(secretRead.decision, 'deny');
assert.equal(secretRead.reason, 'secret_exposure');

const listNames = check(policy, { action: 'vault.opaque.list' });
assert.equal(listNames.decision, 'allow');
assert.equal(listNames.matched_rule, 'vault-list-names');

const opaqueWriteBare = check(policy, { action: 'vault.opaque.write' });
assert.equal(opaqueWriteBare.decision, 'deny');
assert.equal(opaqueWriteBare.reason, 'missing_authorization');

const opaqueWriteOk = check(policy, {
  action: 'vault.opaque.write',
  standing_grant: true,
  diff: { added: ['fieldproof/example'] },
  idempotencyKey: 'vault-write-1',
});
assert.equal(opaqueWriteOk.decision, 'allow');
assert.equal(opaqueWriteOk.receipt.redacted, true);
assert.equal(opaqueWriteOk.receipt.idempotencyKey, 'vault-write-1');
assert.doesNotMatch(JSON.stringify(opaqueWriteOk), /api_key=|password\s*[:=]/i);

const sqConnector = {
  id: 'squarespace-domains',
  ref: 'connector:squarespace-domains',
  health: 'unavailable',
  available: false,
  revoked: false,
  emergencyDisable: false,
  standing_grant: true,
  approver: 'user',
  scopes: ['3labs.io', 'techgizmoguide.com', 'gcpontap.com', 'gsdmanagement.net'],
  capabilities: {
    read: ['domain-inventory', 'dns-read', 'renewal-awareness'],
    mutateDns: ['dns-write'],
    mutateWebsite: ['website-create-update'],
  },
};

const inventory = check(policy, {
  action: 'domain.inventory',
  capability: 'domain-inventory',
  target: '3labs.io',
  connector: sqConnector,
});
assert.equal(inventory.decision, 'allow', 'read-only inventory does not need a live connector');
assert.equal(inventory.matched_rule, 'domain-inventory');

const dnsNoLive = check(policy, {
  action: 'dns.write',
  capability: 'dns-write',
  target: '3labs.io',
  connector: sqConnector,
  standing_grant: true,
  diff: { add: [{ type: 'TXT', name: 'prove', data: 'ok' }] },
  idempotencyKey: 'dns-1',
});
assert.equal(dnsNoLive.decision, 'deny');
assert.equal(dnsNoLive.reason, 'connector_unavailable');

const live = { ...sqConnector, health: 'adopted', available: true };
const expired = check(policy, {
  action: 'dns.write',
  capability: 'dns-write',
  target: '3labs.io',
  connector: live,
  approval: { approvedBy: 'user', expiresAt: '2020-01-01T00:00:00.000Z' },
  diff: { add: [] },
  idempotencyKey: 'dns-exp',
  now: Date.parse('2026-08-16T00:00:00.000Z'),
});
assert.equal(expired.decision, 'deny');
assert.equal(expired.reason, 'approval_expired');

const revoked = check(policy, {
  action: 'dns.write',
  capability: 'dns-write',
  target: '3labs.io',
  connector: { ...live, revoked: true },
  standing_grant: true,
  diff: { add: [] },
  idempotencyKey: 'dns-rev',
});
assert.equal(revoked.decision, 'deny');
assert.equal(revoked.reason, 'connector_revoked');

const emergency = check(policy, {
  action: 'website.update',
  capability: 'website-create-update',
  target: 'techgizmoguide.com',
  connector: { ...live, emergencyDisable: true },
  standing_grant: true,
  diff: { publish: 'draft' },
  idempotencyKey: 'web-1',
});
assert.equal(emergency.decision, 'deny');
assert.equal(emergency.reason, 'emergency_disable');

const scope = check(policy, {
  action: 'dns.write',
  capability: 'dns-write',
  target: 'example.com',
  connector: live,
  standing_grant: true,
  diff: { add: [] },
  idempotencyKey: 'dns-scope',
});
assert.equal(scope.decision, 'deny');
assert.equal(scope.reason, 'scope_mismatch');

const mixedCap = check(policy, {
  action: 'dns.write',
  capability: 'website-create-update',
  target: '3labs.io',
  connector: live,
  standing_grant: true,
  diff: { add: [] },
  idempotencyKey: 'dns-mix',
});
assert.equal(mixedCap.decision, 'deny');
assert.equal(mixedCap.reason, 'capability_mismatch');

const missingDiff = check(policy, {
  action: 'dns.write',
  capability: 'dns-write',
  target: '3labs.io',
  connector: live,
  standing_grant: true,
  idempotencyKey: 'dns-nodiff',
});
assert.equal(missingDiff.decision, 'deny');
assert.equal(missingDiff.reason, 'missing_diff');

const failedVerify = check(policy, {
  action: 'dns.write',
  capability: 'dns-write',
  target: 'gcpontap.com',
  connector: live,
  standing_grant: true,
  diff: { add: [{ type: 'A', name: '@', data: '1.2.3.4' }] },
  idempotencyKey: 'dns-ver',
  verification: { ok: false },
});
assert.equal(failedVerify.decision, 'deny');
assert.equal(failedVerify.reason, 'verification_failed');

const mailgun = check(policy, {
  action: 'dns.write',
  capability: 'dns-write',
  target: '3labs.io',
  connector: live,
  standing_grant: true,
  diff: { remove: [{ type: 'MX', name: '@' }] },
  idempotencyKey: 'dns-mx',
});
assert.equal(mailgun.decision, 'deny');
assert.equal(mailgun.reason, 'mailgun_protected');

const dnsOk = check(policy, {
  action: 'dns.write',
  capability: 'dns-write',
  target: 'gcpontap.com',
  connector: live,
  standing_grant: true,
  diff: { add: [{ type: 'TXT', name: 'prove', data: 'ok' }] },
  idempotencyKey: 'dns-ok',
});
assert.equal(dnsOk.decision, 'allow');
assert.equal(dnsOk.receipt.redacted, true);
assert.equal(dnsOk.receipt.connectorId, 'squarespace-domains');

const overridePolicy = {
  ...policy,
  overrides: [{ id: 'allow-expired-rehearsal', action: 'dns.write', target: 'gcpontap.com', decision: 'allow' }],
};
const overrideExpired = check(overridePolicy, {
  action: 'dns.write',
  capability: 'dns-write',
  target: 'gcpontap.com',
  connector: live,
  approval: { approvedBy: 'user', expiresAt: '2020-01-01T00:00:00.000Z' },
  diff: { add: [] },
  idempotencyKey: 'dns-ov',
  now: Date.parse('2026-08-16T00:00:00.000Z'),
});
assert.equal(overrideExpired.decision, 'allow');
assert.equal(overrideExpired.override_id, 'allow-expired-rehearsal');

const overrideCannotLiftRevoke = check(overridePolicy, {
  action: 'dns.write',
  capability: 'dns-write',
  target: 'gcpontap.com',
  connector: { ...live, revoked: true },
  standing_grant: true,
  diff: { add: [] },
  idempotencyKey: 'dns-ov-rev',
});
assert.equal(overrideCannotLiftRevoke.decision, 'deny');
assert.equal(overrideCannotLiftRevoke.reason, 'connector_revoked');

const receipt = buildReceipt({ action: 'vault.opaque.use', connector: { id: 'keepass-vault', ref: 'keepass:fieldproof' } }, 'allow', 'ok');
assert.equal(receipt.redacted, true);
assert.doesNotMatch(JSON.stringify(receipt), /api_key=|BEGIN [A-Z ]+PRIVATE KEY/);

/* ---------------------------------------------------------------------------
 * Cumulative exposure: the defect a per-action gate cannot see.
 *
 * Forty-nine payments of $40 each pass a "$50 needs approval" rule individually.
 * Every verdict is defensible; the aggregate is an incident. History has to be an
 * input, or determinism just repeats the same correct answer until the money is gone.
 * ------------------------------------------------------------------------- */

const spendPolicy = {
  version: 'test-cumulative',
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

const smallPayment = { action: 'payments.send', params: { amount_usd: 40 } };

// Under the cap: falls through to the ordinary per-action rule.
const under = check(spendPolicy, smallPayment, { committed_usd: 300, intended_usd: 0 });
assert.equal(under.decision, 'require_approval');
assert.equal(under.matched_rule, 'small-payments-ok');

// Over the cap: the same individually-fine payment is denied on aggregate.
const over = check(spendPolicy, smallPayment, { committed_usd: 1960, intended_usd: 0 });
assert.equal(over.decision, 'deny');
assert.equal(over.matched_rule, 'daily-spend-cap');

// In-flight work counts. A burst that has not settled yet must not be invisible to the
// control meant to bound it.
const inFlight = check(spendPolicy, smallPayment, { committed_usd: 400, intended_usd: 150 });
assert.equal(inFlight.decision, 'deny', 'intended spend must count toward the cap');

// No ledger at all: FAIL CLOSED. A cap the caller can skip by omitting state is decorative.
const noLedger = check(spendPolicy, smallPayment);
assert.equal(noLedger.decision, 'deny');
assert.equal(noLedger.ledger_required, true);
assert.match(noLedger.rationale, /no ledger view was supplied/i);

// An empty object is still no answer — zeros must be stated, not assumed.
const emptyLedger = check(spendPolicy, smallPayment, {});
assert.equal(emptyLedger.decision, 'deny');
assert.equal(emptyLedger.ledger_required, true);

// Explicit zeros ARE an answer.
const statedZero = check(spendPolicy, smallPayment, { committed_usd: 0, intended_usd: 0 });
assert.equal(statedZero.decision, 'require_approval');

// Still deterministic: same policy, same request, same ledger, same verdict.
const det1 = check(spendPolicy, smallPayment, { committed_usd: 1960, intended_usd: 0 });
const det2 = check(spendPolicy, smallPayment, { committed_usd: 1960, intended_usd: 0 });
assert.equal(det1.decision, det2.decision);
assert.equal(det1.matched_rule, det2.matched_rule);
assert.equal(det1.rationale, det2.rationale);

// Policies with no cumulative rules are unaffected whether or not a ledger is passed.
const plain = check(spendPolicy.rules ? { ...spendPolicy, rules: [spendPolicy.rules[1]] } : spendPolicy, smallPayment);
assert.equal(plain.decision, 'require_approval');

// An unresolved effect is not a small uncertainty to absorb into the sum. It means the system
// lost track of this quantity, which is exactly when moving more is least defensible.
const unresolved = check(spendPolicy, smallPayment, { committed_usd: 300, intended_usd: 0, unknown_usd: 40 });
assert.equal(unresolved.decision, 'deny');
assert.equal(unresolved.unresolved_intent, true);
assert.match(unresolved.rationale, /observing the target, not by waiting/i);

// It must not be aged out or absorbed: even far under the cap, an outstanding unknown stops it.
const wayUnder = check(spendPolicy, smallPayment, { committed_usd: 1, intended_usd: 0, unknown_usd: 0.01 });
assert.equal(wayUnder.decision, 'deny', 'any outstanding unknown stops, regardless of headroom');

// An explicit zero is a resolved state and must NOT trip it.
const resolved = check(spendPolicy, smallPayment, { committed_usd: 300, intended_usd: 0, unknown_usd: 0 });
assert.equal(resolved.decision, 'require_approval');
assert.equal(resolved.unresolved_intent, undefined);

// Policies with no cumulative rule are unaffected by an unknown they never asked about.
const noCumulative = { ...spendPolicy, rules: [spendPolicy.rules[1]] };
assert.equal(check(noCumulative, smallPayment, { unknown_usd: 999 }).decision, 'require_approval');

console.log('OK — unresolved-intent suite passed (4 checks)');

console.log('OK — cumulative-exposure suite passed (8 checks)');

console.log(`OK — ${pass} verdict cases + 5 engine checks + opaque-connector suite passed`);
