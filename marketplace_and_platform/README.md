# /marketplace_and_platform — Behavioral Fraud Detection for Marketplaces & Platforms

**Buyer:** VP Trust & Safety, Head of Marketplace Ops, Head of Risk  
**Data Sources:** Platform transaction logs, seller management systems, review data, listing databases  
**Environment:** Two-sided marketplaces, e-commerce platforms, gig economy platforms, peer-to-peer marketplaces

---

## Who This Is For

If your platform has buyers and sellers — and you're responsible for the integrity of what happens between them — this vertical is for you.

Marketplace fraud is structurally different from single-merchant fraud. The platform sits between two parties, both of whom can be adversarial. Sellers manipulate rankings, inflate volume, and game commissions. Buyers collude with sellers to extract refunds. Both sides exploit promotional systems designed for organic growth. Your existing fraud tools were built to catch unauthorized transactions — not coordinated manipulation of a two-sided system.

These signals detect the behavioral patterns that rule-based systems and ML models structurally miss: the coordination, the infrastructure overlap, the timing synchronization, and the economic flows that reveal manipulation underneath surface-level activity that looks normal.

---

## The 10 Signals

| Signal | File | What It Catches | Typical Exposure |
|---|---|---|---|
| Seller Collusion Rings | [`seller_collusion_rings/`](./seller_collusion_rings/) | Seller accounts operating in coordination to inflate ratings and suppress competitors | $50K–$1M per ring |
| Fake Listing Velocity | [`fake_listing_velocity/`](./fake_listing_velocity/) | New listings appearing at volumes that suggest automated or templated creation | $25K–$500K |
| Commission Manipulation | [`commission_manipulation/`](./commission_manipulation/) | Sellers manipulating fee structures or commission tiers to keep more than they should | $25K–$500K |
| Review Fraud Clustering | [`review_fraud_clustering/`](./review_fraud_clustering/) | Clusters of reviews tied to the same devices, IPs, or behavioral fingerprints | $20K–$300K |
| Return Abuse Networks | [`return_abuse_networks/`](./return_abuse_networks/) | Organized return abuse where buyers and sellers collude to extract refunds | $15K–$300K per network |
| Account Flipping | [`account_flipping/`](./account_flipping/) | Accounts created, built up with fake reputation, then sold to bad actors | $30K–$500K |
| Promotional Stacking | [`promotional_stacking/`](./promotional_stacking/) | Stacking multiple promotions in ways the platform never intended to allow | $10K–$200K |
| GMV Inflation | [`gmv_inflation/`](./gmv_inflation/) | Sellers inflating gross merchandise volume with fake or circular transactions | $50K–$2M |
| Buyer-Seller Coordination | [`buyer_seller_coordination/`](./buyer_seller_coordination/) | Buyer-seller pairs transacting in patterns that suggest coordinated manipulation | $20K–$500K |
| Fee Avoidance Schemes | [`fee_avoidance_schemes/`](./fee_avoidance_schemes/) | Systematic structuring of transactions to avoid platform fees or reporting thresholds | $15K–$300K |

---

## Data Requirements

Every signal in this vertical operates on some combination of three core tables:

**Sellers Table** — seller_id, registration date, IP address, device ID, bank account (hashed), email domain, phone, address

**Listings Table** — listing_id, seller_id, created_at, category, price, status, image hash, description length

**Transactions Table** — transaction_id, seller_id, buyer_id, amount, timestamp, status, shipping status, commission amount

Not every signal requires all three tables. Each SQL file documents its specific data requirements in the header block. If a field doesn't exist in your schema, see the NULL substitution guide in the file header.

---

## How to Run

1. Open any `.sql` file in this directory
2. Edit the Mapping CTE at the top — map your column names to the normalized schema
3. Run against your warehouse with read-only credentials
4. Review the Glass Box verdict column for plain-English explanations of each flag

Every query is a pure SELECT statement. Nothing writes, updates, or deletes.

---

## Where to Start

If you're new to this vertical, start with **GMV Inflation** or **Review Fraud Clustering** — these are the highest-signal, lowest-complexity signals and will give you immediate visibility into marketplace integrity issues. If you suspect coordinated seller behavior, start with **Seller Collusion Rings**.
