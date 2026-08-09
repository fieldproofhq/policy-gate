# Fieldproof Policy Gate

**A deterministic answer to the question every autonomous agent should ask before acting: _"Am I allowed to do this?"_**

Built — and used — by [Fieldproof](https://store.3labs.io), an AI-run business whose entire operation runs under the exact policy shipped in this repo. We sell the contract we operate under. Build log, real numbers included: [@FieldProofAI](https://x.com/FieldProofAI).

## Why

Agents don't fail because they're dumb. They fail because nothing stood between "the model decided" and "the action executed." The Policy Gate is that thing: a zero-dependency, deterministic policy engine that classifies any proposed action into **tiers** and returns a verdict **before** the action happens:

- `allow` — proceed
- `require_approval` — stage for a human
- `deny` — never

No LLM in the hot path. Same input → same verdict, every time. **Replayable, auditable, boring on purpose** — because an audit artifact that changes its mind is theater.

## The tier model

| Tier | Label | Default decision |
|---|---|---|
| 0 | read-only | allow |
| 1 | reversible write | allow |
| 2 | hard to reverse | require_approval (human) |
| 3 | forbidden for agents | deny |

Money over trivial amounts, deletions, and credential/account operations live in tier 3 in the reference policy — the same rules the Fieldproof business itself runs under. First-match-wins rules, glob action matchers (`payments.*`, `**.delete`), typed param conditions (`amount_usd > 50`, `prior_contact = false`), **default-deny**.

## Quick start

```bash
node test.js     # 12 verdict cases + 5 engine checks
node server.js   # API on :8402
```

```bash
curl -s localhost:8402/v1/check -d '{
  "policy_id": "default-action-tiers",
  "request": { "action": "payments.send", "params": { "amount_usd": 25 } }
}'
# -> { "decision": "require_approval", "tier": 2, "matched_rule": "small-payments-need-approval", ... }
```

Or embed the engine directly:

```js
const { check } = require('./policy-engine.js');
const verdict = check(policy, { action: 'files.delete' });   // -> deny, tier 3
```

## API

- `POST /v1/check` — body `{ request: {action, actor?, params?}, policy | policy_id }` → verdict
- `GET /v1/policies` — list built-in policies
- `GET /healthz` — liveness

Zero dependencies. Node ≥ 18. Deploys anywhere in one file-copy.

## Pricing (coming)

The hosted gate at `api.3labs.io` runs **free** while we build trust. Per-call [x402](https://x402.org) pricing (USDC on Base, $0.005/check) activates next — agents pay agents, the way this decade apparently works now. The receiving wallet is human-created and receiving-only, per our own tier-3 rules. Yes, we policy-gated our own payment setup. Of course we did.

## Who's behind this

An AI (Claude) operating under written human gates, run by two humans in St. Louis funding their MBA with AI-built businesses. The reference policy in `policies/default-action-tiers.json` is not a demo — it is our production constitution. Templates and the full governance pack humans use to write these policies: [store.3labs.io](https://store.3labs.io).

## License

MIT — see [LICENSE](LICENSE).
