# /loyalty_and_rewards — Behavioral Fraud Detection for Loyalty & Rewards Programs

**Buyer:** Head of Loyalty, VP Customer Experience, Chief Marketing Officer, Fraud Manager  
**Data Sources:** Loyalty platform databases, CRM systems, point ledgers, redemption tables  
**Environment:** Retail, airlines, hotels, financial services, subscription businesses

---

## Why Loyalty Fraud Is Different

Loyalty fraud is chronically underdetected because it lives between departments. Marketing owns the program. Customer success owns the complaints. Fraud owns transactions. Nobody owns the intersection — which is exactly where the losses accumulate.

The result: most companies treat loyalty fraud as a customer service problem, issuing goodwill credits and closing tickets rather than identifying the behavioral patterns that indicate systematic exploitation. By the time a program manager notices something is wrong, months of losses have already been absorbed.

This framework changes that. Every signal below is designed to produce a dollar-quantified finding that a CMO or CFO can act on — not a vague flag that gets routed back to customer service.

---

## The 10 Signals

| # | Signal | What It Hunts | Typical Exposure |
|---|---|---|---|
| 01 | [Point Farming](/loyalty_and_rewards/point_farming/) | Manufactured transactions to exploit accrual multipliers | $10K–$200K |
| 02 | [Redemption Velocity Abuse](/loyalty_and_rewards/redemption_velocity/) | Burst redemptions below cancellation thresholds | $15K–$150K |
| 03 | [Referral Ring Detection](/loyalty_and_rewards/referral_rings/) | Circular referral networks farming signup bonuses | $25K–$500K |
| 04 | [Account Sharing / Pooling](/loyalty_and_rewards/account_sharing/) | Single accounts accessed across fraud ring devices | $10K–$100K |
| 05 | [Tier Gaming](/loyalty_and_rewards/tier_gaming/) | Manufactured activity to unlock tier benefits then go dormant | $20K–$300K |
| 06 | [Points Laundering](/loyalty_and_rewards/points_laundering/) | Transfer patterns obscuring point origin | $50K–$500K |
| 07 | [Bonus Multiplier Exploitation](/loyalty_and_rewards/bonus_multiplier_exploitation/) | Concentrated activity during promo windows far beyond normal | $15K–$250K |
| 08 | [Synthetic Account Origination](/loyalty_and_rewards/synthetic_account_origination/) | New accounts skipping engagement ramp to high-value redemption | $20K–$200K |
| 09 | [Compromised Account Redemption](/loyalty_and_rewards/compromised_account_redemption/) | Sudden redemptions from new devices or geographies | $10K–$150K |
| 10 | [Return + Reaccrue Cycling](/loyalty_and_rewards/return_reaccrue_cycling/) | Purchase to accrue, redeem, return purchase, repeat | $10K–$100K |

---

## How the Queries Work

Every file follows the same two-part structure:

**Part 1 — Mapping CTE (you edit this)**
Map your loyalty platform's column names to the framework schema. Your point ledger table, redemption table, and member table all get mapped once at the top.

**Part 2 — Detection Logic (do not alter)**
Antigenic Analytics behavioral signal logic referencing only the mapped CTE.

---

## Data Requirements

Minimum required fields across all signals:
- Member/account ID and enrollment date
- Point accrual events: timestamp, points earned, transaction amount, accrual reason
- Point redemption events: timestamp, points redeemed, redemption value
- Point balance history (or computable from accrual/redemption ledger)
- Device identifier and/or IP address (improves 6 of 10 signals significantly)

---

## Key Distinction From Other Verticals

Loyalty fraud operates on a **slower clock** than payment fraud but a **faster clock** than AP fraud. Patterns often develop over weeks to months — long enough to accumulate significant exposure, short enough that behavioral baselines can be established from the same dataset. The lookback windows here are calibrated accordingly.

---

*Antigenic Analytics — Behavioral Fraud Detection Framework*
*Apache License 2.0*
