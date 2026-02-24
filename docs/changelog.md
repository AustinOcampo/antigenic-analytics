# Changelog

All notable changes to the Antigenic Analytics framework are documented here.
Format: [Version] — Date — Description

---

## [1.0.0] — 2025

### Added
- Root directory structure with three persona-based environments:
  `/payments_and_gateways`, `/procurement_and_ap`, `/identity_and_origination`
- `shared_utilities` directory with universal mapping CTE master template
- Signal 02: Sub-Threshold Batching (full detection query + README)
- Apache 2.0 License
- Root README with signal index and onboarding instructions

### Architecture
- Universal Mapping CTE pattern established as repo-wide standard
- Glass Box Verdict output pattern established as repo-wide standard
- Confidence scoring (HIGH / MEDIUM / LOW) established as repo-wide standard
- All queries read-only (SELECT only — no writes, updates, or deletes)

---

## Upcoming

- Signal 01: Vendor Concentration Ratio
- Signal 03: Billing Code Cycling
- Signal 04: Network Clustering — Shared Identifiers
- Signal 05: Period Boundary Spikes
- Signal 06: Service-to-Outcome Mismatch
- Signal 07: Approval Chain Compression
- Signal 08: New Vendor Ramp
- Signal 09: Duplicate Billing (Morphed)
- Signal 10: Benford's Law Deviation
- Synthetic data CSV (10,000 rows with embedded anomalies)
- Signal stacking / multi-signal scoring query
