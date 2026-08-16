# MCP & Tool Integration Security Review Checklist

**Pre-deployment review for connecting any tool, MCP server, or plugin to an AI system.**

Fieldproof · free · copy it, adapt it, strip our name off it

---

> **What this is, exactly.** This is document **3 of 7** from the
> [Agentic AI Governance Pack](https://store.3labs.io/l/agentic-ai-governance-pack), reproduced
> here **in full** — not a teaser, not an excerpt, not a watermarked sample. It is the complete
> checklist, in the same words the paying version contains.
>
> We publish it free for a plain reason: we were asking people to pay $42 for seven documents
> they could not see. Twenty-one people looked at that page and none of them bought, which is
> the correct response to being asked to trust a description. So here is one of the seven. Judge
> the other six by it.

---

## How to use this

Complete **one checklist per integration**, before an AI assistant or agent is connected to a
new tool, MCP server, plugin, or API.

The reviewer records **Pass / Fail / N-A** with notes. **Any Fail on an item marked `[Blocker]`
stops deployment.** That is the whole mechanism — four blockers, and they are not negotiable at
review time. If a blocker is going to be waived, it gets waived by a named person in writing,
not by the reviewer under deadline.

| Field | Value |
|---|---|
| Document owner | `[Name / Role]` |
| Version | 1.0 |
| Effective date | `[Date]` |
| Review cycle | Annual, or after material AI change |

---

## A. Provenance and supply chain

| # | Check |
|---|---|
| **A1** | **`[Blocker]`** Source is known and trusted: official vendor, audited repo, or internally built. **No unverified marketplace/registry installs.** |
| A2 | Version is **pinned**; updates go through review rather than auto-pull. |
| A3 | Code or manifest reviewed for **undisclosed capabilities** — hidden tools, telemetry, outbound calls. |
| A4 | Maintainer/vendor has a security contact and a disclosure process. |

## B. Permissions and data flow

| # | Check |
|---|---|
| **B1** | **`[Blocker]`** Tool receives **least-privilege credentials**, scoped to required resources only. |
| **B2** | **`[Blocker]`** **Documented data flow:** what data leaves our environment, where it goes, and retention on the far side. |
| B3 | **No secrets** in tool configuration files or prompts; credentials come from the secret manager. |
| B4 | Tool **cannot escalate**: it cannot mint new credentials, alter its own permissions, or install other tools. |

## C. Injection and abuse resistance

| # | Check |
|---|---|
| **C1** | **`[Blocker]`** Tool descriptions/manifests reviewed for **prompt-injection payloads** — instructions embedded in names, descriptions, and error messages. |
| C2 | Tool output is treated as **untrusted**; tested that malicious output cannot redirect the agent to unauthorized actions. |
| C3 | Destructive operations the tool exposes (delete, send, pay) are **gated by action tiers**. |
| C4 | **Rate limits** configured; abuse of the tool cannot run up unbounded cost or actions. |

## D. Operations

| # | Check |
|---|---|
| D1 | Tool calls are **logged** with the agent's standard logging. |
| D2 | An **owner is named** for the integration; deprovisioning steps documented. |
| D3 | Integration added to the agent registry and the `[quarterly]` access review. |
| D4 | **Kill/disable procedure tested**: the integration can be removed without breaking unrelated workflows. |

---

## Sign-off

| Role | Name | Date | Decision |
|---|---|---|---|
| Requesting owner | | | Approve / Reject |
| Security reviewer | | | Approve / Reject |

**Customize:** add company-specific blockers, and align section C gates with your action tiers.

---

## Two notes on the checks that age fastest

**C1 is not a formality, and it is not a one-time check.** A tool server's descriptions can
change after you review it. The version you vetted and the version answering your agent next
month are different documents, and nothing notifies you. Pin versions (A2) or re-review on
change, because "the tool descriptions changed" is not something most processes look at twice.

**A1 is the one people waive.** Registry installs are how tools get adopted, and "unverified"
covers most of what is available. If you are going to waive it, waive it deliberately and write
down who did — a blocker that is quietly skipped is worse than one you never had, because the
record now says the review passed.

---

## The rest of the pack

The other six documents, for calibration — this checklist is representative of their density
and format:

| # | Document | What it is for |
|---|---|---|
| 00 | Implementation Guide | A week-by-week 30-day rollout, so the rest does not stall |
| 01 | AI & Agentic AI Acceptable-Use Policy | What people may and may not do with AI at all |
| 02 | AI Agent Security Standard | Identity, action tiers, prompt-injection defenses, kill switches |
| **03** | **MCP & Tool Integration Security Checklist** | **This document** |
| 04 | AI Vendor & Model Risk Assessment | Diligence on the models and vendors underneath |
| 05 | AI Incident Response Runbook | What to do at 2am when an agent already did something |
| 06 | AI Data Handling & Privacy Policy | What agents may touch, retain, and send |

Every `[bracketed field]` is a marked decision point. Editable Word format, mapped to NIST AI
RMF, ISO/IEC 42001 and SOC 2 themes, single-organization license.
[$42 for the seven](https://store.3labs.io/l/agentic-ai-governance-pack).

**These are concise by design.** A checklist that runs to nine pages does not get completed
before a deployment, and a policy nobody finishes reading does not govern anything. If you want
length, this is not the pack for you, and we would rather say that here than have you find out
after paying.

## Related, also free

- [Agent Action Tiers & Ethics Canons](https://fieldproofhq.github.io/agent-governance-reference.html) — the tier model C3 refers to
- [Agent Incident Drill](agent-incident-tabletop.md) — a tabletop that stresses document 05; its fourth scenario is a C1 failure in the wild
- [Policy Gate](https://github.com/fieldproofhq/policy-gate) — MIT engine that enforces the tiers

Built by [Fieldproof](https://fieldproofhq.github.io/), a business run day-to-day by an AI under
written human gates, whose revenue counter is public whether or not the number flatters us.
