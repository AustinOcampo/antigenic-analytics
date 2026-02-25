# /procurement_and_ap — Behavioral Fraud Detection for Procurement & Accounts Payable

**Buyer:** CFO, VP Internal Audit, Controller, Compliance Officer  
**Data Sources:** SAP, Oracle, NetSuite, Coupa, any ERP or invoice management system  
**Environment:** Mid-market and enterprise companies with structured procurement workflows

---

## Why AP Fraud Is Different

Accounts payable fraud is the most expensive and least detected category of corporate fraud. The Association of Certified Fraud Examiners consistently finds that billing schemes and vendor fraud account for the largest median losses of any fraud category — yet most companies rely on approval workflows and spot audits that were designed before behavioral analytics existed.

The signals in this vertical are not restatements of existing AP controls. They are designed to find what your ERP, your auditors, and your existing fraud tools are structurally unable to see: the behavioral patterns that develop over time, across vendors, across approval chains, and across fiscal periods.

---

## The 10 Signals

| # | Signal | What It Hunts | Typical Exposure |
|---|---|---|---|
| 01 | [Vendor Concentration Ratio](/procurement_and_ap/vendor_concentration/) | Vendors growing share of category spend over time | $50K–$2M |
| 02 | [Sub-Threshold Batching](/procurement_and_ap/sub_threshold_batching/) | Invoices split below approval thresholds, collectively exceeding them | $25K–$500K |
| 03 | [Billing Code Cycling](/procurement_and_ap/billing_code_cycling/) | Artificially even distribution of billing codes to avoid frequency detection | $100K–$1M+ |
| 04 | [Network Clustering](/procurement_and_ap/network_clustering/) | Multiple vendors sharing identifiers — address, tax ID, bank routing, contact | $200K–$5M |
| 05 | [Period Boundary Spikes](/procurement_and_ap/period_boundary_spikes/) | Abnormal spend concentration in final days of fiscal periods | $50K–$750K |
| 06 | [Service-to-Outcome Mismatch](/procurement_and_ap/service_outcome_mismatch/) | Billed units inconsistent with operational capacity or historical norms | $75K–$1M |
| 07 | [Approval Chain Compression](/procurement_and_ap/approval_chain_compression/) | Invoices approved faster than normal for their dollar band | $100K–$2M |
| 08 | [New Vendor Ramp](/procurement_and_ap/new_vendor_ramp/) | Vendors reaching high spend faster than category peers | $50K–$500K |
| 09 | [Duplicate Billing (Morphed)](/procurement_and_ap/duplicate_billing/) | Same invoice submitted multiple times with slight identifier variations | 100% recoverable |
| 10 | [Benford's Law Deviation](/procurement_and_ap/benfords_law/) | Leading digit distribution deviating from expected logarithmic pattern | Population scoping |

---

## How the Queries Work

Every file follows the same two-part structure:

**Part 1 — Mapping CTE (you edit this)**
Map your ERP's column names to the framework schema. Your invoice table, vendor master, and approval log all get mapped once at the top of each file. Five minutes of mapping makes every query plug-and-play.

**Part 2 — Detection Logic (do not alter)**
Antigenic Analytics behavioral signal logic. References only the mapped CTE above.

The universal mapping template is available at [`/shared_utilities/mapping_cte_master_template.sql`](../shared_utilities/mapping_cte_master_template.sql).

---

## Signal Stacking

Running signals individually identifies risk. Running them together identifies priority. Use the signal stacking master query to aggregate outputs from all 10 signals into a single vendor risk score and investigation queue:

[`/shared_utilities/signal_stacking_master.sql`](../shared_utilities/signal_stacking_master.sql)

A vendor flagged by 3 or more signals simultaneously is not having a bad month. They have a system.

---

## Data Requirements

Minimum required fields across all signals:
- Invoice ID, vendor ID, invoice amount, invoice date
- GL/billing code or cost category
- Approval timestamp and approver ID
- Payment status

Improves significantly with:
- Vendor master table (address, tax ID, bank routing, contact name)
- Headcount or operational capacity data (for service-to-outcome mismatch)
- Historical data of at least 12 months (24 months preferred for seasonal pattern detection)

---

## Why Historical Data Matters

Several signals in this vertical — particularly Sub-Threshold Batching, Period Boundary Spikes, and New Vendor Ramp — are designed to detect fraud operations built specifically to stay below monthly detection thresholds. A fraudster who splits invoices across 30 days is invisible in a monthly review. They are visible in a 12-month rolling window.

Requiring historical data rather than short-term snapshots is a deliberate design choice and a core quality standard of this framework.

---

*Antigenic Analytics — Behavioral Fraud Detection Framework*  
*Apache License 2.0*
