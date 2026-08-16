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

console.log(`OK — ${pass} verdict cases + 5 engine checks + opaque-connector suite passed`);
