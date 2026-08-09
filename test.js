'use strict';
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const { check, globMatch } = require('./policy-engine.js');

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

console.log(`OK — ${pass} verdict cases + 5 engine checks passed`);
