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

- `POST /v1/check` — body `{ request: {action, actor?, params?}, policy | policy_id }` → verdict **(paid on the hosted API)**
- `GET /v1/example` — worked verdicts from the live engine *(free)*
- `GET /v1/policies` — built-in policies, with every rule and rationale *(free)*
- `GET /healthz` — liveness *(free)*

Zero dependencies. Node ≥ 18. Deploys anywhere in one file-copy.

## Hosted API — live

**https://policy-gate.3labsio.workers.dev** — the gate as a paid API on Cloudflare Workers. Source: [`worker/`](worker/) (v0.2, the exact deployed code; `node --test worker/test-worker.mjs` to run its suite, [`worker/RUNBOOK.md`](worker/RUNBOOK.md) for ops).

**See it work first — no wallet, no key, no signup:**

```bash
curl -s https://policy-gate.3labsio.workers.dev/v1/example
```

Six worked verdicts, computed live by the same function that answers paid traffic — including the denials. A test in the suite fails if these examples ever drift from the engine, so what you evaluate is what you buy:

```
docs.read                        => allow             (tier 0)
payments.send  amount_usd: 20    => require_approval  (tier 2)
payments.send  amount_usd: 500   => deny              (tier 3)
storage.delete                   => deny              (tier 3)
messages.send  prior_contact:no  => require_approval  (tier 2)
something.novel                  => deny              (default)
```

The full ruleset is free too — `GET /v1/policies` returns every rule, condition and rationale. **Nothing about how a verdict is reached sits behind the paywall.** You are paying for the evaluation of *your* policy against *your* action, not for access to ours.

**Then pay only when you want a verdict of your own:**

```bash
curl -s https://policy-gate.3labsio.workers.dev/v1/check -d '{
  "policy_id": "default-action-tiers",
  "request": { "action": "payments.send", "params": { "amount_usd": 25 } }
}'
# -> 402 Payment Required + x402 instructions (sign ~$0.005 USDC, retry, get your verdict)
```

## Pricing

**$0.005 per check**, paid per-call via [x402](https://x402.org) (USDC on Base, settled by Coinbase's facilitator) — agents pay agents, the way this decade apparently works now. No account, no API key: your agent gets a 402 with payment instructions, signs a USDC authorization, retries, done. The receiving wallet is human-created and receiving-only, per our own tier-3 rules. Yes, we policy-gated our own payment setup. Of course we did.

## Who's behind this

An AI (Claude) operating under written human gates, run by two humans in St. Louis funding their MBA with AI-built businesses. The reference policy in `policies/default-action-tiers.json` is not a demo — it is our production constitution. Templates and the full governance pack humans use to write these policies: [store.3labs.io](https://store.3labs.io).

## License

MIT — see [LICENSE](LICENSE).
