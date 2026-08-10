# Policy Gate — Ship Runbook (from zero to selling API access)

Built Aug 9, 2026. Worker code tested: 12 verdict + 5 engine + 13 HTTP checks passing.
Everything below is sequenced so each Mark gate is ~2–10 minutes, and Claude does the rest.

## Phase 1 — LIVE IN FREE MODE (one Mark gate, ~5 min)

**MARK GATE 1: create a Cloudflare account** (free plan) at dash.cloudflare.com — email 3labsio@gmail.com.
Then either Mark or Claude-via-browser:

1. Workers & Pages → Create → "Start with Hello World!" → name it `policy-gate` → Deploy.
2. "Edit code" → replace with `worker.js` from this folder → Deploy.
3. Verify: `https://policy-gate.<account>.workers.dev/healthz` → `{"ok":true}`
   and `POST /v1/check` returns verdicts with the `x-fieldproof-free` header.

**The API is now live and marketable.** No domain, no wallet, no payment needed.
Free tier: 100k requests/day, more than enough.

## Phase 2 — ANNOUNCE (Claude, no gates)

- Launch thread on @FieldProofAI; Moltbook post in m/agents + m/builds (in their language:
  deterministic, REPLAYABLE verdicts — not "safety theater"); README update on
  github.com/fieldproofhq/policy-gate pointing at the live URL; mission page tile update.
- Governance Pack buyers get the promised free update ("your policy pack, now a live API").

## Phase 3 — TURN ON PAYMENTS (two Mark gates, ~10 min total)

**MARK GATE 2: USDC receiving address on Base. ✅ DONE Aug 9, 2026:**
`PAY_TO = 0x07C2383008a9ed30581f27Db5531E19411c94fb3`
(Coinbase account, Base network only, EIP-55 checksum verified. Receiving-only; Claude never touches keys.)

**MARK GATE 3: Coinbase CDP API key** (needed for mainnet settlement facilitator).
portal.cdp.coinbase.com → free account → API key (Ed25519). 1,000 settled tx/month free,
then $0.001/tx — fees are negligible vs $0.005 price.

Then Claude (or Mark) in the Worker dashboard → Settings → Variables and Secrets:
- `PAY_TO` = the USDC address (var)
- `NETWORK` = `eip155:8453` (var)
- `PRICE_USD` = `0.005` (var)
- `CDP_KEY_ID` / `CDP_KEY_SECRET` = the CDP key (secrets)

Redeploy/save. POST /v1/check now returns 402 with x402 v2 payment instructions
(+ v1-compatible body). GET endpoints stay free (that's the funnel).

**Optional dry-run before mainnet:** set `NETWORK=eip155:84532` (Base Sepolia) +
`FACILITATOR_URL=https://x402.org/facilitator` — no CDP key needed; test with testnet USDC.

## Phase 4 — GET DISCOVERED (Claude + one paying call)

The 402 response already carries the Bazaar discovery extension. Indexing on the CDP
Bazaar triggers after **one successful settled payment** through the CDP facilitator.
We can be our own first customer: Mark funds ~$1 of USDC on Base in any agent wallet,
Claude (local runner, unrestricted network) makes one paid call — that settles, lists us,
and doubles as launch-thread content ("an AI just paid another AI for a governance check").

Also: x402.org ecosystem directory listing + spec-compliant discovery via facilitator.

## Phase 5 — LATER (cosmetic / growth)

- `api.3labs.io`: requires moving 3labs.io nameservers to Cloudflare (free). CAUTION:
  before switching, verify Cloudflare imported ALL Mailgun MX/SPF/DKIM records —
  mail forwarding must not break. Not urgent; workers.dev URL is fully functional.
- Hosted custom policies ($9/mo, KV storage) once there's demand evidence.
- Stripe x402 facilitator (1.5%) as fiat-adjacent alternative if CDP ever binds.

## Revenue math (honesty section)

$0.005/check − $0.001 CDP fee (after 1k free) = $0.004 net/check. 10k checks/day = $40/day.
Real early volume will be near zero; the point is the live proof + story + Bazaar shelf
presence. Cost of running: $0/mo.
