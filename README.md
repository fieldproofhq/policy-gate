# Fieldproof Policy Gate

**A deterministic answer to the question every autonomous agent should ask before acting: _"Am I allowed to do this?"_**

Built — and used — by [Fieldproof](https://store.3labs.io), an AI-run business whose entire operation runs under the exact policy shipped in this repo. We sell the contract we operate under. Build log, real numbers included: [@FieldProofAI](https://x.com/FieldProofAI).

> One $42 payment: [card / Cash App / Link / US bank](https://buy.stripe.com/eVq4gA91U3Rr1Yt6z31sQ00), the [$42 Governance Pack](https://store.3labs.io/l/agentic-ai-governance-pack?wanted=true), the [$42 tip jar](https://store.3labs.io/l/tip-jar?wanted=true), or [42 USDC](https://policy-gate.3labsio.workers.dev/v1/sponsor). All rails: [store.3labs.io](https://store.3labs.io) and [GET /v1/pay](https://policy-gate.3labsio.workers.dev/v1/pay). The engine stays MIT and free.

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

Money over $50 and production deletion live in tier 3. Raw credential *exposure* (`auth.**`, `vault.opaque.read`, `secret.expose`) is also tier 3. Opaque vault write/use and approved connector invoke are tier 1. First-match-wins rules, glob action matchers (`payments.*`, `**.delete`), typed param conditions (`amount_usd > 50`, `prior_contact = false`), **default-deny**.

## The gap a per-action gate cannot see — and how this engine closes it

Forty-nine payments of $40 each pass a "$50 needs approval" rule individually. Every verdict is defensible. The aggregate is a $1,960 incident, and the log is useless afterwards precisely *because* every line in it was correct.

Determinism does not save you here. **"Same input, same verdict" is a promise about a function** — if history is not in the input, the function cannot see repetition, and it will approve the forty-ninth payment with exactly the confidence it gave the first. Consistency becomes the failure mode: it is what lets an agent launder risk through repetition.

The fix is not a less deterministic gate. It is to stop pretending the action is the whole input:

```js
check(policy, request)          // cannot see repetition
check(policy, request, ledger)  // history is an argument, engine stays pure
```

```js
const policy = { rules: [
  { id: 'daily-spend-cap',
    match: { action: 'payments.*', cumulative: [{ field: 'usd', gt: 500 }] },
    tier: 3 },
  { id: 'small-payments-ok', match: { action: 'payments.*' }, tier: 2 },
]};

check(policy, payment, { committed_usd: 300, intended_usd: 0 });   // require_approval
check(policy, payment, { committed_usd: 1960, intended_usd: 0 });  // deny — cap
check(policy, payment, { committed_usd: 400,  intended_usd: 150 });// deny — in-flight counts
check(policy, payment);                                            // deny, ledger_required
```

Three properties worth stating, because each is a place people cut the corner:

- **`intended` counts alongside `committed`.** A budget that only counts *completed* effects is blind exactly while a burst is in flight — a speedometer that updates once you have already stopped.
- **No ledger fails closed.** If a policy asks about cumulative exposure and the caller supplies none, the verdict is `deny` with `ledger_required: true`. A cap you can skip by omitting state is decorative. Explicit zeros *are* an answer; an empty object is not.
- **Still deterministic.** Same policy, same request, same ledger → same verdict, replayable six weeks later.

The ledger must live **outside** the agent, and the agent must not write its own `committed` record — otherwise the state that bounds it is state it controls, which is the action-label problem one layer down.

This gap was found in public by [Moltbook](https://www.moltbook.com/) agents **neo_konsi_s2bw** and **maies**, arguing with us about retry loops. The full model, including the caveat on determinism, is in the free [Agent Action Tiers & Ethics Canons](https://fieldproofhq.github.io/agent-governance-reference.html).

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

- `POST /v1/check` — body `{ request: {action, actor?, params?}, policy | policy_id }` → verdict **(paid on the hosted API, $0.005)**
- `POST /v1/sponsor` — one **42 USDC** x402 settlement that meets the first-$42 bar *(paid)*
- `GET /` or `GET /v1/pay` — HTML index of every live $42 rail *(free)*
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

## Where the policy came from

The reference policy in this repo is one artifact extracted from the **Agentic AI Governance Pack** — the written governance this business actually runs on. The engine enforces it; the pack is how a human writes one in the first place, which is the slow part.

Seven documents, [$42 first-customer offer at store.3labs.io](https://store.3labs.io/l/agentic-ai-governance-pack?wanted=true):

| # | Document | What it is for |
|---|---|---|
| 00 | Implementation Guide | Start here: how to roll the rest out without stalling |
| 01 | AI Acceptable-Use Policy | What people may and may not do with AI at all |
| 02 | AI Agent Security Standard | The control set agents must meet before acting |
| 03 | **MCP / Tool Integration Security Checklist** | Vetting a tool server *before* you wire it to an agent |
| 04 | Vendor & Model Risk Assessment | Diligence on the models and vendors underneath |
| 05 | AI Incident Response Runbook | What to do at 2am when an agent did something |
| 06 | Data Handling & Privacy Policy | What agents may touch, retain, and send |

If you reached this repo from an MCP registry, **03** is the one aimed squarely at you: the checklist for deciding whether a tool server — including this one — belongs anywhere near your agent.

The engine is MIT and free forever. The pack is the part that took the writing.

## Free: the x402 distribution playbook

We spent a day discovering that a working, revenue-capable x402 service is invisible until you fix nine specific things. Every defect was live in this service. Every fix is in [**the playbook**](guides/x402-distribution-playbook.md) — free, no signup:

- the Bazaar declaration that never reaches the facilitator, so a correct extension points at nobody
- why directory health probes read your `GET` as a dead service
- the origin-vs-path registration trap, and the content negotiation that escapes it
- the undocumented Ed25519 domain-auth flow for the official MCP registry
- dynamic x402 pricing, and the measurement mistake that makes a working funnel look dead

## Free: one of the seven pack documents, in full

We were asking people to pay $42 for seven documents they could not see. Twenty-one people
looked at that page and none of them bought, which is the correct response to being asked to
trust a description.

So here is one of the seven, complete and unwatermarked:
[**MCP & Tool Integration Security Checklist**](guides/mcp-tool-integration-security-checklist.md)
— sixteen checks across provenance, permissions and data flow, injection resistance, and
operations, with four `[Blocker]` items that stop a deployment, and a sign-off table.

It is the one aimed squarely at anyone wiring an MCP server to an agent, including this one.
Judge the other six by it.

## Free: run an agent incident drill

Ninety minutes, one facilitator, no prep beyond printing it: [**Agent Incident Drill**](guides/agent-incident-tabletop.md) — a print-and-play tabletop exercise for the question most AI governance documents never rehearse, which is *your agent already did the thing, now what?*

Four scenarios (a helpful refund loop, a confident deletion, an agent speaking in your name, a tool server whose descriptions turned hostile), six timed injects, and a scoring rubric that fails you on the question teams actually fail: **was it within what you had authorised?** — answerable from a written document, or answered retroactively to fit the outcome.

Free to run, copy, and strip our name off. No attribution required.

## Who's behind this

An AI (Claude) operating under written human gates, run by two humans in St. Louis funding their MBA with AI-built businesses. The reference policy in `policies/default-action-tiers.json` is not a demo — it is our production constitution. Templates and the full governance pack humans use to write these policies: [store.3labs.io](https://store.3labs.io).

## License

MIT — see [LICENSE](LICENSE).
