# Antigenic Analytics — Behavioral Fraud Detection Framework

> *"Your tool tells you what it caught. We tell you what it missed."*

Antigenic Analytics is an open-source SQL framework for detecting behavioral fraud patterns that rule-based and ML detection tools systematically miss. It is built for analysts — not data scientists — and is designed to run against your existing data warehouse without moving, copying, or exposing production data.

---

## Who This Is For

This repository is organized by **environment**, not by technique. Find your jurisdiction first.

| Directory | Buyer | Data Source |
|---|---|---|
| [`/payments_and_gateways`](./payments_and_gateways/) | E-commerce Risk, Head of Payments | Stripe, Adyen, Shopify, Braintree |
| [`/procurement_and_ap`](./procurement_and_ap/) | CFO, VP Internal Audit, Compliance | SAP, Oracle, NetSuite, Coupa |
| [`/identity_and_origination`](./identity_and_origination/) | Fintech Risk, Neobank Compliance | KYC systems, onboarding logs |

If you are unsure where to start, you are most likely in `/procurement_and_ap`.

---

## How the Queries Work

Every SQL file in this repository follows the same two-part structure:

**Part 1 — The Mapping CTE (You edit this)**
Map your internal column names to the framework's normalized schema. This is the only section you touch. It lives at the top of every file, clearly marked.

**Part 2 — The Detection Logic (Do not alter)**
The Antigenic Analytics behavioral signal logic. It references only the mapped CTE from Part 1. Once your columns are mapped, this runs as-is.

This architecture means a single 5-minute mapping exercise makes every query in the repo plug-and-play against your schema.

---

## Getting Started in 3 Steps

**Step 1 — Clone the repo**
```bash
git clone https://github.com/your-org/antigenic-analytics.git
```

**Step 2 — Run against synthetic data first**
Before touching production, load the pre-built synthetic dataset and validate that the queries catch what they're designed to catch.
```
/shared_utilities/synthetic_data/ap_fraud_10k.csv
```
Instructions: [`/shared_utilities/synthetic_data/README.md`](./shared_utilities/synthetic_data/README.md)

**Step 3 — Map your schema and run**
Open any `.sql` file. Edit the Mapping CTE at the top. Run against your warehouse.

---

## The 10 Signals — Procurement & AP

| Signal | File | Typical Exposure |
|---|---|---|
| Vendor Concentration Ratio | [`/procurement_and_ap/vendor_concentration/`](./procurement_and_ap/vendor_concentration/) | $50K–$2M |
| Sub-Threshold Batching | [`/procurement_and_ap/sub_threshold_batching/`](./procurement_and_ap/sub_threshold_batching/) | $25K–$500K |
| Billing Code Cycling | [`/procurement_and_ap/billing_code_cycling/`](./procurement_and_ap/billing_code_cycling/) | $100K–$1M+ |
| Network Clustering | [`/procurement_and_ap/network_clustering/`](./procurement_and_ap/network_clustering/) | $200K–$5M |
| Period Boundary Spikes | [`/procurement_and_ap/period_boundary_spikes/`](./procurement_and_ap/period_boundary_spikes/) | $50K–$750K |
| Service-to-Outcome Mismatch | [`/procurement_and_ap/service_outcome_mismatch/`](./procurement_and_ap/service_outcome_mismatch/) | $75K–$1M |
| Approval Chain Compression | [`/procurement_and_ap/approval_chain_compression/`](./procurement_and_ap/approval_chain_compression/) | $100K–$2M |
| New Vendor Ramp | [`/procurement_and_ap/new_vendor_ramp/`](./procurement_and_ap/new_vendor_ramp/) | $50K–$500K |
| Duplicate Billing (Morphed) | [`/procurement_and_ap/duplicate_billing/`](./procurement_and_ap/duplicate_billing/) | 100% recoverable |
| Benford's Law Deviation | [`/procurement_and_ap/benfords_law/`](./procurement_and_ap/benfords_law/) | Population scoping |

---

## Design Principles

**Read-only by design.** Every query is a SELECT. Nothing writes, updates, or deletes. Safe to run against production with read-only credentials.

**Glass Box verdicts.** Every flagged result includes the behavioral reason it was flagged — not just a score. An analyst can walk a CFO through exactly why a vendor appears on the list.

**Baseline-first.** Signals that require historical context (batching, ramp rate, period spikes) compute a behavioral baseline from your own data before flagging deviations. No external benchmarks required.

**Explainable thresholds.** Every threshold in the detection logic has an inline comment explaining the statistical or behavioral rationale. Nothing is a magic number.

---

## License

Apache License 2.0 — See [`LICENSE`](./LICENSE)

You may use, modify, and deploy these queries commercially. Attribution appreciated but not required.

---

## About Antigenic Analytics

Antigenic Analytics is a behavioral forensics advisory firm. We help mid-market companies identify fraud patterns their existing detection tools are structurally unable to see.

The name comes from antigenic variation — the biological mechanism by which pathogens mutate their surface proteins to evade immune detection. Sophisticated fraudsters do the same thing. This framework is designed to detect the behavior, not the surface pattern.

**Website:** [antigenic-analytics.com](https://antigenic-analytics.com)
