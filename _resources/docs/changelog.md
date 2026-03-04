# Changelog — Antigenic Analytics

All notable changes to this framework are documented here.

---

## [1.3.0] — 2026-02-25

### Added
- `/identity_and_origination` vertical — 5 signals for fintech and neobank fraud detection
  - Synthetic Identity Detection
  - Velocity at Origination
  - KYC Bypass Indicators
  - Mule Account Detection
  - First-Party Fraud — Bust-Out Pattern
- Updated root README to reflect all four verticals and full 35-signal count

---

## [1.2.0] — 2026-02-25

### Added
- `/loyalty_and_rewards` vertical — 10 signals for loyalty and rewards program fraud
  - Point Farming
  - Redemption Velocity Abuse
  - Referral Ring Detection
  - Account Sharing / Pooling
  - Tier Gaming
  - Points Laundering
  - Bonus Multiplier Exploitation
  - Synthetic Account Origination
  - Compromised Account Redemption
  - Return + Reaccrue Cycling

---

## [1.1.0] — 2026-02-24

### Added
- `/payments_and_gateways` vertical — 10 signals for e-commerce and payment fraud
  - Refund Abuse
  - Promo Farming
  - Card Testing
  - Velocity Fraud
  - Friendly Fraud — Chargeback Abuse
  - Triangulation Fraud
  - BIN Attacks
  - Account Takeover at Checkout
  - Return Fraud
  - Synthetic Transaction Patterns

---

## [1.0.0] — 2026-02-24

### Added
- Initial release of the Antigenic Analytics behavioral fraud detection framework
- `/procurement_and_ap` vertical — 10 signals for AP and procurement fraud
  - Vendor Concentration Ratio
  - Sub-Threshold Batching
  - Billing Code Cycling
  - Network Clustering
  - Period Boundary Spikes
  - Service-to-Outcome Mismatch
  - Approval Chain Compression
  - New Vendor Ramp
  - Duplicate Billing (Morphed)
  - Benford's Law Deviation
- `/shared_utilities` — Mapping CTE master template and signal stacking master query
- Apache 2.0 License
