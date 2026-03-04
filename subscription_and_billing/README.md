# /subscription_and_billing — Behavioral Fraud Detection for Subscription & Recurring Billing

**Buyer:** Head of Growth, VP Finance, Revenue Ops, Head of Payments  
**Data Sources:** Billing systems (Stripe Billing, Recurly, Chargebee), subscription platforms, usage logs, session data  
**Environment:** SaaS companies, D2C subscription brands, streaming services, membership platforms

---

## Who This Is For

If your revenue model depends on recurring payments — and you're losing money to trial abuse, chargeback farming, credential sharing, or users gaming your billing logic — this vertical is for you.

Subscription fraud doesn't look like traditional payment fraud. There are no stolen credit cards and no unauthorized transactions. Instead, it's a slow bleed: users who never intended to pay extracting value from your trial periods, your refund policies, your tier structures, and your promotional pricing. Each individual account looks borderline acceptable. The pattern only surfaces when you connect the behavioral fingerprints across accounts and across time.

These signals detect the infrastructure reuse, timing patterns, and billing manipulation that your existing subscription management tools were never designed to catch.

---

## The 10 Signals

| Signal | File | What It Catches | Typical Exposure |
|---|---|---|---|
| Trial Abuse Cycling | [`trial_abuse_cycling/`](./trial_abuse_cycling/) | Free trial signups from the same devices and payment fingerprints cycling through new accounts endlessly | $5K–$100K |
| Recurring Dispute Abuse | [`recurring_dispute_abuse/`](./recurring_dispute_abuse/) | Users disputing recurring charges months into a subscription they actively used | $10K–$200K |
| Credential Sharing Detection | [`credential_sharing_detection/`](./credential_sharing_detection/) | Credential sharing patterns where a single account is accessed from dozens of locations simultaneously | $5K–$100K per account |
| Promo Window Exploitation | [`promo_window_exploitation/`](./promo_window_exploitation/) | Bulk account creation timed to coincide with promotional pricing windows | $10K–$150K |
| Payment Decay Patterns | [`payment_decay_patterns/`](./payment_decay_patterns/) | Payment methods that succeed for the trial period then conveniently fail before the first real charge | $5K–$80K |
| Tier Manipulation | [`tier_manipulation/`](./tier_manipulation/) | Accounts downgrading and upgrading in patterns designed to exploit billing gaps between tiers | $5K–$75K |
| Renewal Refund Timing | [`renewal_refund_timing/`](./renewal_refund_timing/) | Refund requests clustered around renewal dates from users who consumed the full billing period | $5K–$100K |
| Untraceable Payment Methods | [`untraceable_payment_methods/`](./untraceable_payment_methods/) | Gift cards and prepaid methods used specifically to avoid traceability on recurring charges | $5K–$50K per cluster |
| Plan Stacking | [`plan_stacking/`](./plan_stacking/) | Coordinated signups that share behavioral fingerprints but use different identities to stack family or team plans | $5K–$50K |
| Churn-and-Return Cycling | [`churn_and_return_cycling/`](./churn_and_return_cycling/) | Accounts that hit usage limits, churn, re-sign up under a new identity, and repeat the cycle | $10K–$150K |

---

## Data Requirements

Signals in this vertical operate across several data surfaces depending on the specific fraud pattern:

**Accounts Table** — account_id, created_at, subscription_plan, trial dates, device_id, ip_address, payment_method_fingerprint, cancellation date

**Charges Table** — charge_id, account_id, amount, charge_date, status, dispute_date, dispute_reason, payment_method_type, billing_cycle_number

**Usage / Sessions Table** — account_id, activity_date, login_count, actions_count, session_device_id, session_ip_address, session_city

**Plan Changes Table** — account_id, old_plan, new_plan, change_timestamp, old_price, new_price (for Tier Manipulation signal)

**Members Table** — member_id, plan_id, added_at, device_id, ip_address (for Plan Stacking signal)

Not every signal requires all tables. Each SQL file documents its specific data requirements in the header block. If a field doesn't exist in your schema, the signal will still run — optional fields degrade gracefully.

---

## How to Run

1. Open any `.sql` file in this directory
2. Edit the Mapping CTE at the top — map your column names to the normalized schema
3. Run against your warehouse with read-only credentials
4. Review the Glass Box verdict column for plain-English explanations of each flag

Every query is a pure SELECT statement. Nothing writes, updates, or deletes.

---

## Where to Start

If you're seeing chargeback spikes, start with **Recurring Dispute Abuse** and **Renewal Refund Timing** — these connect usage data to dispute patterns and immediately reveal who's gaming your refund policy. If you suspect trial abuse at scale, start with **Trial Abuse Cycling** — it clusters accounts by shared infrastructure and exposes the device/payment fingerprints behind serial trial signups.
