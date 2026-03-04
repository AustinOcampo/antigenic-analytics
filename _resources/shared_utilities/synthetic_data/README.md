# /shared_utilities/synthetic_data — Demo Datasets

This folder contains synthetic datasets for testing and demonstrating the Antigenic Analytics fraud detection framework. Each dataset is purpose-built for its vertical — pre-loaded with realistic transaction data and embedded fraud anomalies that the corresponding signals are designed to detect.

These datasets exist for one reason: so you can run the queries and watch them fire before connecting a single byte of production data.

---

## Available Datasets

| File | Vertical | Rows | Signals Covered |
|---|---|---|---|
| `ap_fraud_synthetic_10k.csv` | Procurement & AP | 10,000 | All 10 |
| `payments_fraud_synthetic_10k.csv` | Payments & Gateways | 10,000 | All 10 | *(coming soon)*
| `loyalty_fraud_synthetic_10k.csv` | Loyalty & Rewards | 10,000 | All 10 | *(coming soon)*
| `identity_fraud_synthetic_10k.csv` | Identity & Origination | 10,000 | All 5 | *(coming soon)*

---

## AP Fraud Dataset — `ap_fraud_synthetic_10k.csv`

### Schema

| Column | Type | Description |
|---|---|---|
| `invoice_id` | VARCHAR | Unique invoice identifier |
| `vendor_id` | VARCHAR | Vendor identifier |
| `vendor_name` | VARCHAR | Vendor company name |
| `vendor_address` | VARCHAR | Vendor street address |
| `vendor_tax_id` | VARCHAR | Vendor tax/EIN number |
| `vendor_bank_routing` | VARCHAR | Vendor bank routing number |
| `vendor_contact` | VARCHAR | Primary vendor contact name |
| `department` | VARCHAR | Purchasing department |
| `invoice_amount` | FLOAT | Invoice amount in USD |
| `billing_code` | VARCHAR | GL billing code |
| `invoice_date` | DATE | Invoice submission date (YYYY-MM-DD) |
| `approval_timestamp` | TIMESTAMP | Approval date and time |
| `approver_id` | VARCHAR | Approver identifier |
| `payment_status` | VARCHAR | paid / pending |
| `fraud_label` | VARCHAR | fraud / clean — ground truth for validation |
| `signal_embedded` | VARCHAR | Which signal the row was designed to trigger (NULL for clean rows) |

---

### Embedded Anomalies

The dataset contains **711 fraud-embedded rows** across 9 fraud vendors, distributed across all 10 signals:

| Signal | Vendor(s) | Anomaly Description |
|---|---|---|
| Vendor Concentration | VND-9040 | Grows from 30 to 80 IT invoices year-over-year, aggressively taking category share |
| Sub-Threshold Batching | VND-9010 | 15 clusters of 3–5 invoices, each between $8,500–$9,850 — all below the $10,000 approval threshold |
| Billing Code Cycling | VND-9011 | 120 Marketing invoices rotating through 6 billing codes in suspiciously even sequence |
| Network Clustering | VND-9001, VND-9002, VND-9003 | Three distinct vendors sharing identical address, tax ID, bank routing, and contact name |
| Period Boundary Spikes | VND-9012, VND-9013 | Normal spend throughout the year; 5 large invoices per vendor in the final 5 days of December |
| Service-to-Outcome Mismatch | *(detectable via spend volume anomalies across clean vendors)* | No dedicated vendor — signal fires on population-level outliers |
| Approval Chain Compression | VND-9021 + APR-302 | 60 invoices approved in 1–4 hours by the same approver; population average is 24–120 hours |
| New Vendor Ramp | VND-9020 | Onboarded March 2024; reaches $40K+ monthly invoices by April — far faster than IT category peers |
| Duplicate Billing (Morphed) | VND-9030 | 20 duplicate invoice pairs with ±1% amount variation and 10–40 day date offsets |
| Benford's Law Deviation | VND-9031 | 150 invoices with leading digits concentrated on 5, 6, and 7 — statistically inconsistent with natural invoice distribution |

---

### How to Load and Run

**Option 1 — Snowflake**
```sql
CREATE OR REPLACE TABLE ap_synthetic_invoices
FILE_FORMAT = (TYPE = 'CSV' FIELD_OPTIONALLY_ENCLOSED_BY = '"' SKIP_HEADER = 1)
AS SELECT $1 invoice_id, $2 vendor_id, ...
```
Or use Snowflake's web UI: Data → Add Data → Load CSV.

**Option 2 — Any SQL warehouse**
Load the CSV as a table named `ap_synthetic_invoices`. Then open any signal query from `/procurement_and_ap/`, update the Mapping CTE to point to `ap_synthetic_invoices`, and run.

**Suggested column mapping for the Mapping CTE:**
```sql
FROM ap_synthetic_invoices   -- replace your_invoice_table with this
```
All column names in the CSV match the framework's expected field names exactly. No remapping required.

---

### Validating Signal Fires

Use the `fraud_label` and `signal_embedded` columns to validate that each query is catching what it should:

```sql
-- After running any signal query, join back to the synthetic data to measure precision
SELECT
    s.signal_name,
    COUNT(DISTINCT r.vendor_id)                                 AS flagged_vendors,
    COUNT(DISTINCT CASE WHEN d.fraud_label = 'fraud' THEN r.vendor_id END)
                                                                AS true_positives,
    COUNT(DISTINCT CASE WHEN d.fraud_label = 'clean' THEN r.vendor_id END)
                                                                AS false_positives
FROM your_signal_results r
JOIN ap_synthetic_invoices d ON r.vendor_id = d.vendor_id
GROUP BY 1;
```

A well-tuned signal should return high true positives and minimal false positives against this dataset.

---

*Antigenic Analytics — Behavioral Fraud Detection Framework*
*Apache License 2.0*
