# Antigenic Analytics — Behavioral Fraud Detection Framework

> *"Your tool tells you what it caught. We tell you what it missed."*

Antigenic Analytics is an open-source SQL framework for detecting behavioral fraud patterns that rule-based and ML detection tools systematically miss. It is built for analysts — not data scientists — and is designed to run against your existing data warehouse without moving, copying, or exposing production data.

---

## Who This Is For

This repository is organized by **environment**, not by technique. Find your jurisdiction first.

| Directory | Buyer | Data Source |
|---|---|---|
| [`/procurement_and_ap`](./procurement_and_ap/) | CFO, VP Internal Audit, Compliance | SAP, Oracle, NetSuite, Coupa |
| [`/payments_and_gateways`](./payments_and_gateways/) | Head of Risk, VP Operations, Fraud Manager | Stripe, Adyen, Shopify, Braintree |
| [`/loyalty_and_rewards`](./loyalty_and_rewards/) | Head of Loyalty, VP Customer, CMO | Loyalty platforms, CRM, point ledgers |
| [`/identity_and_origination`](./identity_and_origination/) | Chief Risk Officer, Head of Compliance | KYC systems, onboarding logs, core banking |

If you are unsure where to start, you are most likely in `/procurement_and_ap`.

---

## How the Queries Work

Every SQL file in this repository follows the same two-part structure:

**Part 1 — The Mapping CTE (You edit this)**
Map your internal column names to the framework's normalized schema. This is the only section you touch. It lives at the top of every file, clearly marked.

**Part 2 — The Detection Logic (Do not alter)**
The Antigenic Analytics behavioral signal logic. It references only the mapped CTE from Part 1. Once your columns are mapped, this runs as-is.

This architecture means a single 5-minute mapping exercise makes every query in the vertical plug-and-play against your schema. The universal mapping template is available at [`/shared_utilities/mapping_cte_master_template.sql`](./shared_utilities/mapping_cte_master_template.sql).

---

## Getting Started in 3 Steps

**Step 1 — Clone the repo**
```bash
git clone https://github.com/AustinOcampo/antigenic-analytics.git
```

**Step 2 — Find your vertical**
Navigate to the directory that matches your data environment. Each vertical has its own README with signal descriptions, data requirements, and buyer context.

**Step 3 — Map your schema and run**
Open any `.sql` file. Edit the Mapping CTE at the top. Run against your warehouse with read-only credentials.

---

## The 35 Signals

### Procurement & AP — 10 Signals
*For: CFO, VP Internal Audit, Compliance | Data: SAP, Oracle, NetSuite, Coupa*

| Signal | Typical Exposure |
|---|---|
| [Vendor Concentration Ratio](./procurement_and_ap/vendor_concentration/) | $50K–$2M |
| [Sub-Threshold Batching](./procurement_and_ap/sub_threshold_batching/) | $25K–$500K |
| [Billing Code Cycling](./procurement_and_ap/billing_code_cycling/) | $100K–$1M+ |
| [Network Clustering](./procurement_and_ap/network_clustering/) | $200K–$5M |
| [Period Boundary Spikes](./procurement_and_ap/period_boundary_spikes/) | $50K–$750K |
| [Service-to-Outcome Mismatch](./procurement_and_ap/service_outcome_mismatch/) | $75K–$1M |
| [Approval Chain Compression](./procurement_and_ap/approval_chain_compression/) | $100K–$2M |
| [New Vendor Ramp](./procurement_and_ap/new_vendor_ramp/) | $50K–$500K |
| [Duplicate Billing (Morphed)](./procurement_and_ap/duplicate_billing/) | 100% recoverable |
| [Benford's Law Deviation](./procurement_and_ap/benfords_law/) | Population scoping |

---

### Payments & Gateways — 10 Signals
*For: Head of Risk, VP Operations, Fraud Manager | Data: Stripe, Adyen, Shopify, Braintree*

| Signal | Typical Exposure |
|---|---|
| [Refund Abuse](./payments_and_gateways/refund_abuse/) | $10K–$500K |
| [Promo Farming](./payments_and_gateways/promo_farming/) | $25K–$250K |
| [Card Testing](./payments_and_gateways/card_testing/) | Processor penalties |
| [Velocity Fraud](./payments_and_gateways/velocity_fraud/) | $50K–$1M |
| [Friendly Fraud — Chargeback Abuse](./payments_and_gateways/friendly_fraud/) | $15K–$300K |
| [Triangulation Fraud](./payments_and_gateways/triangulation_fraud/) | $50K–$500K |
| [BIN Attacks](./payments_and_gateways/bin_attacks/) | Scheme penalties |
| [Account Takeover at Checkout](./payments_and_gateways/account_takeover/) | $20K–$200K |
| [Return Fraud](./payments_and_gateways/return_fraud/) | $10K–$150K |
| [Synthetic Transaction Patterns](./payments_and_gateways/synthetic_transactions/) | $100K–$2M |

---

### Loyalty & Rewards — 10 Signals
*For: Head of Loyalty, VP Customer Experience, CMO | Data: Loyalty platforms, CRM, point ledgers*

| Signal | Typical Exposure |
|---|---|
| [Point Farming](./loyalty_and_rewards/point_farming/) | $10K–$200K |
| [Redemption Velocity Abuse](./loyalty_and_rewards/redemption_velocity/) | $15K–$150K |
| [Referral Ring Detection](./loyalty_and_rewards/referral_rings/) | $25K–$500K |
| [Account Sharing / Pooling](./loyalty_and_rewards/account_sharing/) | $10K–$100K |
| [Tier Gaming](./loyalty_and_rewards/tier_gaming/) | $20K–$300K |
| [Points Laundering](./loyalty_and_rewards/points_laundering/) | $50K–$500K |
| [Bonus Multiplier Exploitation](./loyalty_and_rewards/bonus_multiplier_exploitation/) | $15K–$250K |
| [Synthetic Account Origination](./loyalty_and_rewards/synthetic_account_origination/) | $20K–$200K |
| [Compromised Account Redemption](./loyalty_and_rewards/compromised_account_redemption/) | $10K–$150K |
| [Return + Reaccrue Cycling](./loyalty_and_rewards/return_reaccrue_cycling/) | $10K–$100K |

---

### Identity & Origination — 5 Signals
*For: Chief Risk Officer, Head of Compliance, VP Fraud | Data: KYC systems, onboarding logs, core banking*

| Signal | Typical Exposure |
|---|---|
| [Synthetic Identity Detection](./identity_and_origination/synthetic_identity/) | $5K–$50K per account |
| [Velocity at Origination](./identity_and_origination/velocity_at_origination/) | $10K–$500K per ring |
| [KYC Bypass Indicators](./identity_and_origination/kyc_bypass_indicators/) | $5K–$100K per account |
| [Mule Account Detection](./identity_and_origination/mule_account_detection/) | $20K–$1M per network |
| [First-Party Fraud — Bust-Out Pattern](./identity_and_origination/bust_out_pattern/) | $10K–$200K per account |

---

## Design Principles

**Read-only by design.** Every query is a SELECT. Nothing writes, updates, or deletes. Safe to run against production with read-only credentials.

**Glass Box verdicts.** Every flagged result includes the behavioral reason it was flagged — not just a score. An analyst can walk a CFO through exactly why a vendor, customer, or account appears on the list.

**Baseline-first.** Signals compute a behavioral baseline from your own data before flagging deviations. No external benchmarks, no industry averages, no black-box comparisons. Your data defines what normal looks like.

**Explainable thresholds.** Every threshold in the detection logic has an inline comment explaining the statistical or behavioral rationale. Nothing is a magic number.

**Complementary, not competitive.** These signals are designed to find what your existing fraud tools missed — not to replace them. The value proposition is the gap.

---

## Shared Utilities

| File | Purpose |
|---|---|
| [`/shared_utilities/mapping_cte_master_template.sql`](./shared_utilities/mapping_cte_master_template.sql) | Universal schema mapping template for any vertical |
| [`/shared_utilities/signal_stacking_master.sql`](./shared_utilities/signal_stacking_master.sql) | Aggregate AP signal outputs into a composite risk score |

---

## License

Apache License 2.0 — See [`LICENSE`](./LICENSE)

You may use, modify, and deploy these queries commercially. Attribution appreciated but not required.

---

## About Antigenic Analytics

Antigenic Analytics is a behavioral forensics advisory firm. We help mid-market companies identify fraud patterns their existing detection tools are structurally unable to see.

The name comes from antigenic variation — the biological mechanism by which pathogens mutate their surface proteins to evade immune detection. Sophisticated fraudsters do the same thing: they adapt their methods specifically to stay below the detection thresholds of the tools watching them. This framework is designed to detect the behavior underneath the surface — the patterns that don't change even when the tactics do.

**Website:** [antigenic-analytics.com](https://antigenic-analytics.com)
