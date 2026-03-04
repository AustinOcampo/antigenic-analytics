# Antigenic Analytics — Behavioral Fraud Detection Framework

> *"Your tool tells you what it caught. We tell you what it missed."*

Antigenic Analytics is an open-source SQL framework for detecting behavioral fraud patterns that rule-based and ML detection tools systematically miss. It is built for analysts — not data scientists — and is designed to run against your existing data warehouse without moving, copying, or exposing production data.

---

## Who This Is For

This repository is organized by **environment**, not by technique. Find your jurisdiction first.

| Directory | Buyer | Data Source |
| --- | --- | --- |
| [`/loyalty_rewards_and_promotion`](/loyalty_rewards_and_promotion) | Head of Loyalty, VP Customer Experience, Growth | Loyalty platforms, CRM, point ledgers, promo engines |
| [`/ecommerce_and_payments`](/ecommerce_and_payments) | Head of Risk, VP Operations, Fraud Manager | Stripe, Adyen, Shopify, Braintree |
| [`/marketplace_and_platform`](/marketplace_and_platform) | VP Trust & Safety, Head of Marketplace Ops | Platform transaction logs, seller systems, review data |
| [`/subscription_and_billing`](/subscription_and_billing) | Head of Growth, VP Finance, Revenue Ops | Billing systems, subscription platforms, usage logs |

If you are unsure where to start, you are most likely in `/ecommerce_and_payments`.

---

## How the Queries Work

Every SQL file in this repository follows the same two-part structure:

**Part 1 — The Mapping CTE (You edit this)**
Map your internal column names to the framework's normalized schema. This is the only section you touch. It lives at the top of every file, clearly marked.

**Part 2 — The Detection Logic (Do not alter)**
The Antigenic Analytics behavioral signal logic. It references only the mapped CTE from Part 1. Once your columns are mapped, this runs as-is.

This architecture means a single 5-minute mapping exercise makes every query in the vertical plug-and-play against your schema. The universal mapping template is available at [`/shared_utilities/mapping_cte_master_template.sql`](/shared_utilities/mapping_cte_master_template.sql).

---

## Getting Started in 3 Steps

**Step 1 — Clone the repo**

```
git clone https://github.com/AustinOcampo/antigenic-analytics.git
```

**Step 2 — Find your vertical**
Navigate to the directory that matches your data environment. Each vertical has its own README with signal descriptions, data requirements, and buyer context.

**Step 3 — Map your schema and run**
Open any `.sql` file. Edit the Mapping CTE at the top. Run against your warehouse with read-only credentials.

---

## The 43 Signals

### Loyalty, Rewards & Promotion Fraud — 13 Signals

*For: Head of Loyalty, VP Customer Experience, Growth | Data: Loyalty platforms, CRM, point ledgers, promo engines*

| Signal | What It Catches |
| --- | --- |
| Point Farming | Accounts earning points at volumes no real customer could organically generate |
| Referral Ring Detection | Fake referral networks where the same devices or addresses keep showing up |
| Tier Gaming | Users manipulating tier qualifications to unlock benefits they didn't earn |
| Points Laundering | Points moved through chains of accounts to obscure where they originated |
| Bonus Multiplier Exploitation | Bonus promotions triggered repeatedly using coordinated timing and multiple accounts |
| Dormant Account Harvesting | Dormant accounts suddenly reactivated and drained of accumulated value |
| Compromised Account Redemption | Redemptions happening from locations or devices the real member has never used |
| Synthetic Member Detection | New accounts created with synthetic identities just to harvest sign-up bonuses |
| Cross-Program Arbitrage | Members exploiting gaps between partner programs to double-dip on value |
| Redemption Velocity Abuse | Velocity patterns in earning or redemption that no legitimate shopping behavior explains |
| Promo Code Stacking | Promo codes stacked or reused in ways the platform never intended to allow |
| First-Time Discount Farming | Fake accounts created solely to harvest first-time customer discounts repeatedly |
| Coupon Network Distribution | Coupon codes resold or distributed through networks outside your intended audience |

---

### E-Commerce & Payments Fraud — 10 Signals

*For: Head of Risk, VP Operations, Fraud Manager | Data: Stripe, Adyen, Shopify, Braintree*

| Signal | What It Catches |
| --- | --- |
| Card Testing | Thousands of small-dollar authorizations testing stolen cards against your checkout |
| BIN Attacks | Coordinated attacks targeting specific card ranges to find valid numbers |
| Refund Abuse | Refund requests that look legitimate individually but form patterns of organized abuse |
| Velocity Fraud | Transaction volumes from single accounts or devices that no real customer would generate |
| Friendly Fraud | Customers disputing charges they actually made, knowing you'll eat the loss |
| Triangulation Fraud | Stolen goods purchased on your site and resold through a third party |
| Account Takeover | Legitimate accounts quietly taken over and used before the real customer notices |
| Synthetic Transactions | Transactions that look normal on paper but were never initiated by a real human |
| Chargeback Farming | Serial disputants cycling through payment methods to repeat the same scheme |
| Payment Method Cycling | Users rotating cards, emails, and devices to look like new customers every time |

---

### Marketplace & Platform Fraud — 10 Signals

*For: VP Trust & Safety, Head of Marketplace Ops | Data: Platform transaction logs, seller systems, review data*

| Signal | What It Catches |
| --- | --- |
| Seller Collusion Rings | Seller accounts operating in coordination to inflate ratings and suppress competitors |
| Fake Listing Velocity | New listings appearing at volumes that suggest automated or templated creation |
| Commission Manipulation | Sellers manipulating fee structures or commission tiers to keep more than they should |
| Review Fraud Clustering | Clusters of reviews tied to the same devices, IPs, or behavioral fingerprints |
| Return Abuse Networks | Organized return abuse where buyers and sellers collude to extract refunds |
| Account Flipping | Accounts created, built up with fake reputation, then sold to bad actors |
| Promotional Stacking | Stacking multiple promotions in ways the platform never intended to allow |
| GMV Inflation | Sellers inflating gross merchandise volume with fake or circular transactions |
| Buyer-Seller Coordination | Buyer-seller pairs transacting in patterns that suggest coordinated manipulation |
| Fee Avoidance Schemes | Systematic structuring of transactions to avoid platform fees or reporting thresholds |

---

### Subscription & Recurring Billing Fraud — 10 Signals

*For: Head of Growth, VP Finance, Revenue Ops | Data: Billing systems, subscription platforms, usage logs*

| Signal | What It Catches |
| --- | --- |
| Trial Abuse Cycling | Free trial signups from the same devices and payment fingerprints cycling through new accounts endlessly |
| Recurring Dispute Abuse | Users disputing recurring charges months into a subscription they actively used |
| Credential Sharing Detection | Credential sharing patterns where a single account is accessed from dozens of locations simultaneously |
| Promo Window Exploitation | Bulk account creation timed to coincide with promotional pricing windows |
| Payment Decay Patterns | Payment methods that succeed for the trial period then conveniently fail before the first real charge |
| Tier Manipulation | Accounts downgrading and upgrading in patterns designed to exploit billing gaps between tiers |
| Renewal Refund Timing | Refund requests clustered around renewal dates from users who consumed the full billing period |
| Untraceable Payment Methods | Gift cards and prepaid methods used specifically to avoid traceability on recurring charges |
| Plan Stacking | Coordinated signups that share behavioral fingerprints but use different identities to stack family or team plans |
| Churn-and-Return Cycling | Accounts that hit usage limits, churn, re-sign up under a new identity, and repeat the cycle |

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
| --- | --- |
| [`/shared_utilities/mapping_cte_master_template.sql`](/shared_utilities/mapping_cte_master_template.sql) | Universal schema mapping template for any vertical |
| [`/shared_utilities/signal_stacking_master.sql`](/shared_utilities/signal_stacking_master.sql) | Aggregate signal outputs into a composite risk score |

---

## License

Apache License 2.0 — See [`LICENSE`](/LICENSE)

You may use, modify, and deploy these queries commercially. Attribution appreciated but not required.

---

## About Antigenic Analytics

Antigenic Analytics is a behavioral fraud detection framework for e-commerce, marketplace, and subscription businesses. We help mid-market companies identify fraud patterns their existing detection tools are structurally unable to see.

The name comes from antigenic variation — the biological mechanism by which pathogens mutate their surface proteins to evade immune detection. Sophisticated fraudsters do the same thing: they adapt their methods specifically to stay below the detection thresholds of the tools watching them. This framework is designed to detect the behavior underneath the surface — the patterns that don't change even when the tactics do.

**Website:** [austinocampo.github.io/antigenic-analytics](https://austinocampo.github.io/antigenic-analytics)
