# /payments_and_gateways — Behavioral Fraud Detection for E-Commerce & Payments

**Buyer:** Head of Risk, VP Operations, Fraud Manager  
**Data Sources:** Stripe, Shopify, Adyen, Braintree, PayPal, custom payment tables  
**Environment:** E-commerce, DTC brands, marketplaces, subscription businesses

---

## Who This Is For

If your fraud stack tells you what it blocked, this tells you what it missed.

These signals are designed for analysts with access to transaction-level payment data. They do not require ML models, external data feeds, or vendor integrations. Every query runs against your existing warehouse.

---

## The 10 Signals

| # | Signal | What It Hunts | Typical Exposure |
|---|---|---|---|
| 01 | [Refund Abuse](/payments_and_gateways/refund_abuse/) | Customers engineering refunds as a revenue stream | $10K–$500K |
| 02 | [Promo Farming](/payments_and_gateways/promo_farming/) | Coordinated discount and coupon extraction | $25K–$250K |
| 03 | [Card Testing](/payments_and_gateways/card_testing/) | Automated small-charge validation of stolen cards | Chargeback liability |
| 04 | [Velocity Fraud](/payments_and_gateways/velocity_fraud/) | Burst transaction patterns exploiting approval windows | $50K–$1M |
| 05 | [Friendly Fraud — Chargeback Abuse](/payments_and_gateways/friendly_fraud/) | Legitimate customers weaponizing the dispute process | $15K–$300K |
| 06 | [Triangulation Fraud](/payments_and_gateways/triangulation_fraud/) | Stolen cards funding real orders through a fraudulent storefront | $50K–$500K |
| 07 | [BIN Attacks](/payments_and_gateways/bin_attacks/) | Sequential card number enumeration against your checkout | Processor penalties |
| 08 | [Account Takeover at Checkout](/payments_and_gateways/account_takeover/) | Hijacked accounts used for rapid high-value purchasing | $20K–$200K |
| 09 | [Return Fraud](/payments_and_gateways/return_fraud/) | Systematic exploitation of return and exchange policies | $10K–$150K |
| 10 | [Synthetic Transaction Patterns](/payments_and_gateways/synthetic_transactions/) | Fabricated transaction sequences that mimic legitimate behavior | $100K–$2M |

---

## How the Queries Work

Every file follows the same two-part structure:

**Part 1 — Mapping CTE (you edit this)**  
Map your Stripe, Shopify, or internal column names to the framework schema. Five minutes of mapping makes every query plug-and-play.

**Part 2 — Detection Logic (do not alter)**  
Antigenic Analytics behavioral signal logic. References only the mapped CTE.

---

## Key Difference From AP Signals

Payments fraud moves faster than procurement fraud. Where AP signals look for patterns over weeks and months, payment signals often fire within hours or days. The rolling windows here are tighter, the velocity thresholds are lower, and the Glass Box verdicts are designed to be actioned same-day — not in a quarterly review.

---

## Data Requirements

Minimum required fields across all signals:
- Transaction ID, amount, timestamp
- Customer/account identifier
- Payment method identifier (card, wallet)
- Transaction status (approved, declined, refunded, disputed)
- IP address (improves 6 of 10 signals significantly)
- Shipping address (improves 3 of 10 signals)

---

*Antigenic Analytics — Behavioral Fraud Detection Framework*  
*Apache License 2.0*
