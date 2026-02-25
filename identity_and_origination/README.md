# /identity_and_origination — Behavioral Fraud Detection for Fintech & Neobanks

**Buyer:** Head of Risk, Chief Compliance Officer, VP Fraud, Credit Risk Manager  
**Data Sources:** KYC platforms, onboarding systems, core banking, credit decisioning engines  
**Environment:** Neobanks, BNPL providers, digital lenders, fintech credit products

---

## Why Identity Fraud Is Different

Every other fraud vertical in this framework catches fraud after the relationship begins. Identity and origination fraud happens before it — at the application layer, during KYC, and in the first 30–90 days of account life.

By the time a synthetic identity shows up in your transaction data, the account has already been opened, credit has already been extended, and the extraction window is already open. The only way to catch it cost-effectively is to detect the behavioral signals at origination — before the account is funded.

This vertical is designed for exactly that.

---

## The 5 Signals

| # | Signal | What It Hunts | Typical Exposure |
|---|---|---|---|
| 01 | [Synthetic Identity](/identity_and_origination/synthetic_identity/) | Identity components that don't cohere — SSN/age mismatches, thin-file anomalies | $5K–$50K per account |
| 02 | [Velocity at Origination](/identity_and_origination/velocity_at_origination/) | Burst application patterns from shared device, IP, or identity components | $10K–$500K per ring |
| 03 | [KYC Bypass Indicators](/identity_and_origination/kyc_bypass_indicators/) | Behavioral anomalies in the verification event itself | $5K–$100K per account |
| 04 | [Mule Account Detection](/identity_and_origination/mule_account_detection/) | Accounts used purely for pass-through money movement | $20K–$1M per network |
| 05 | [First-Party Fraud — Bust-Out Pattern](/identity_and_origination/bust_out_pattern/) | Deliberate credit buildup followed by maximum drawdown before charge-off | $10K–$200K per account |

---

## Key Data Requirements

These signals require access to data that sits upstream of your transaction tables:

- **Application data:** submitted identity fields, application timestamp, device/IP at submission
- **KYC event data:** document type, verification result, attempt count, timestamps
- **Account opening data:** funding method, initial deposit, account type
- **Early account behavior:** first 90 days of transaction, balance, and transfer activity
- **Credit data (for bust-out):** credit limit, utilization history, payment history

---

## Detection Philosophy

Identity fraud signals fire earliest and lose power over time. A synthetic identity that passes KYC and survives 6 months of account seasoning becomes progressively harder to detect behaviorally. The signals in this vertical are optimized for the **first 90 days** — the window where behavioral fingerprints are still distinct from legitimate customers who may superficially look similar.

After 90 days, bust-out detection (Signal 05) is your primary remaining tool.

---

*Antigenic Analytics — Behavioral Fraud Detection Framework*  
*Apache License 2.0*
