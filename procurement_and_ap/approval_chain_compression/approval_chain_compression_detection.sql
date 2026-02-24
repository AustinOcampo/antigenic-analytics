-- =============================================================================
-- ANTIGENIC ANALYTICS — SIGNAL: APPROVAL CHAIN COMPRESSION
-- =============================================================================
-- File:     approval_chain_compression_detection.sql
-- Signal:   07 of 10 — Procurement & AP
-- Version:  1.0.0
-- License:  Apache 2.0
--
-- WHAT THIS DETECTS:
-- Invoices that move through the approval process significantly faster than
-- is operationally normal — particularly for high-dollar or unusual invoices.
-- When an approver is colluding with a vendor, they don't let invoices sit in
-- the normal review queue. They push them through. Speed is the fingerprint.
--
-- BEHAVIORAL TELL:
-- A $75,000 invoice approved in four hours when the average invoice at that
-- dollar level takes three days is not efficiency — it's exposure. Run this
-- analysis at the approver level and you will often find one person who
-- consistently fast-tracks invoices from a specific vendor.
--
-- DATA REQUIREMENTS:
-- Requires: vendor_id, vendor_name, invoice_amount, submitted_timestamp,
--           approval_timestamp, approved_by
-- NOTE: If approval timestamps are not stored separately from submission,
--       this signal cannot run. See NULL substitution guide in the master template.
--
-- TUNING PARAMETERS:
-- * fast_approval_percentile — approvals faster than this percentile are flagged (default: 10th)
-- * min_invoice_amount       — minimum invoice value to analyze (default: $5,000)
-- * min_invoices_per_approver — minimum invoices for an approver baseline (default: 10)
--
-- TYPICAL EXPOSURE RANGE: $100,000 — $2,000,000
-- =============================================================================


-- =============================================================================
-- STEP 1: MAP YOUR COLUMNS AND SET YOUR THRESHOLDS
-- =============================================================================

WITH normalized_ledger AS (

    SELECT
        invoice_id              AS transaction_id,          -- expected: VARCHAR
        vendor_id               AS vendor_id,               -- expected: VARCHAR
        vendor_name             AS vendor_name,             -- expected: VARCHAR
        invoice_amount          AS invoice_amount,          -- expected: FLOAT
        invoice_date            AS invoice_date,            -- expected: DATE
        cost_center_id          AS cost_center_id,          -- expected: VARCHAR
        submitted_at            AS submitted_timestamp,     -- expected: TIMESTAMP_NTZ
        approved_at             AS approval_timestamp,      -- expected: TIMESTAMP_NTZ
        approved_by_user_id     AS approved_by,             -- expected: VARCHAR
        approval_level          AS approval_level           -- expected: VARCHAR or INTEGER (NULL ok)

    FROM your_internal_table_name   -- << CHANGE THIS

    WHERE
        invoice_date >= DATEADD('year', -2, CURRENT_DATE)
        AND payment_status NOT IN ('VOIDED', 'CANCELLED')
        AND approved_at IS NOT NULL                         -- only approved invoices
        AND submitted_at IS NOT NULL

),

thresholds AS (
    SELECT
        10      AS fast_approval_percentile,    -- Flag approvals faster than 10th percentile
        5000    AS min_invoice_amount,          -- Minimum invoice amount to analyze
        10      AS min_invoices_per_approver    -- Minimum invoices for approver baseline
),


-- =============================================================================
-- STEP 2: ANTIGENIC ANALYTICS DETECTION LOGIC
-- =============================================================================

-- Compute approval time in hours for every invoice
approval_times AS (
    SELECT
        transaction_id,
        vendor_id,
        vendor_name,
        invoice_amount,
        invoice_date,
        cost_center_id,
        approved_by,
        approval_level,
        submitted_timestamp,
        approval_timestamp,
        DATEDIFF('hour', submitted_timestamp, approval_timestamp)
                                                AS approval_hours,
        -- Dollar band: group invoices into tiers for peer comparison
        CASE
            WHEN invoice_amount < 10000         THEN 'Under $10K'
            WHEN invoice_amount < 25000         THEN '$10K–$25K'
            WHEN invoice_amount < 50000         THEN '$25K–$50K'
            WHEN invoice_amount < 100000        THEN '$50K–$100K'
            ELSE 'Over $100K'
        END                                     AS dollar_band
    FROM normalized_ledger
    CROSS JOIN thresholds t
    WHERE invoice_amount >= t.min_invoice_amount
      AND DATEDIFF('hour', submitted_timestamp, approval_timestamp) >= 0
),

-- Baseline: normal approval time per dollar band across all approvers
dollar_band_baseline AS (
    SELECT
        dollar_band,
        PERCENTILE_CONT(0.10) WITHIN GROUP (ORDER BY approval_hours)
                                                AS p10_approval_hours,
        PERCENTILE_CONT(0.50) WITHIN GROUP (ORDER BY approval_hours)
                                                AS median_approval_hours,
        PERCENTILE_CONT(0.90) WITHIN GROUP (ORDER BY approval_hours)
                                                AS p90_approval_hours,
        AVG(approval_hours)                     AS avg_approval_hours,
        COUNT(*)                                AS total_invoices_in_band
    FROM approval_times
    GROUP BY 1
),

-- Approver-level baseline: how fast does each approver normally move?
approver_baseline AS (
    SELECT
        approved_by,
        dollar_band,
        AVG(approval_hours)                     AS approver_avg_hours,
        PERCENTILE_CONT(0.10) WITHIN GROUP (ORDER BY approval_hours)
                                                AS approver_p10_hours,
        COUNT(*)                                AS approver_invoice_count
    FROM approval_times
    GROUP BY 1, 2
),

-- Join baselines and flag fast approvals
invoices_with_baseline AS (
    SELECT
        a.*,
        b.p10_approval_hours                    AS band_p10_hours,
        b.median_approval_hours                 AS band_median_hours,
        b.avg_approval_hours                    AS band_avg_hours,
        ab.approver_avg_hours,
        ab.approver_invoice_count,
        t.min_invoices_per_approver,
        -- Is this approval fast relative to the dollar band?
        CASE WHEN a.approval_hours <= b.p10_approval_hours THEN 1 ELSE 0 END
                                                AS fast_vs_band_baseline,
        -- Is this approval fast relative to the approver's own typical speed?
        CASE WHEN a.approval_hours <= ab.approver_p10_hours THEN 1 ELSE 0 END
                                                AS fast_vs_approver_baseline
    FROM approval_times a
    JOIN dollar_band_baseline b ON a.dollar_band = b.dollar_band
    LEFT JOIN approver_baseline ab
        ON  a.approved_by = ab.approved_by
        AND a.dollar_band = ab.dollar_band
    CROSS JOIN thresholds t
    WHERE
        a.approval_hours <= b.p10_approval_hours    -- Faster than 10th percentile for this $ band
),

-- Aggregate to approver-vendor combinations for pattern detection
approver_vendor_patterns AS (
    SELECT
        approved_by,
        vendor_id,
        vendor_name,
        cost_center_id,
        dollar_band,
        COUNT(*)                                AS fast_approval_count,
        SUM(invoice_amount)                     AS total_fast_approved_spend,
        AVG(approval_hours)                     AS avg_fast_approval_hours,
        MIN(approval_hours)                     AS fastest_approval_hours,
        AVG(band_avg_hours)                     AS normal_approval_hours_for_band,
        MAX(approver_invoice_count)             AS approver_total_invoice_count,
        MIN(invoice_date)                       AS first_fast_approval,
        MAX(invoice_date)                       AS last_fast_approval
    FROM invoices_with_baseline
    GROUP BY 1, 2, 3, 4, 5
)


-- =============================================================================
-- FINAL OUTPUT — GLASS BOX VERDICT
-- =============================================================================

SELECT
    approved_by                                             AS approver_id,
    vendor_id,
    vendor_name,
    cost_center_id,
    dollar_band,

    -- COMPRESSION METRICS
    fast_approval_count                                     AS invoices_fast_approved,
    total_fast_approved_spend,
    ROUND(avg_fast_approval_hours, 1)                       AS avg_approval_time_hours,
    fastest_approval_hours                                  AS fastest_single_approval_hours,
    ROUND(normal_approval_hours_for_band, 1)                AS normal_hours_for_this_dollar_band,
    ROUND(normal_approval_hours_for_band - avg_fast_approval_hours, 1)
                                                            AS hours_faster_than_normal,
    first_fast_approval,
    last_fast_approval,
    approver_total_invoice_count,

    -- CONFIDENCE
    CASE
        WHEN fast_approval_count >= 5
         AND total_fast_approved_spend >= 50000            THEN 'HIGH — Repeated Pattern, High Spend'
        WHEN fast_approval_count >= 3                      THEN 'MEDIUM — Multiple Fast Approvals'
        ELSE 'LOW'
    END                                                     AS signal_confidence,

    'Approval Chain Compression'                            AS signal_name,
    'Approver ' || approved_by || ' fast-tracked '
        || fast_approval_count::VARCHAR || ' invoices from '
        || vendor_name || ' totaling $'
        || ROUND(total_fast_approved_spend, 0)::VARCHAR
        || '. Average approval time: ' || ROUND(avg_fast_approval_hours, 1)::VARCHAR
        || ' hours vs. ' || ROUND(normal_approval_hours_for_band, 1)::VARCHAR
        || ' hours normal for ' || dollar_band || ' invoices.'
                                                            AS glass_box_verdict

FROM approver_vendor_patterns
WHERE fast_approval_count >= 2  -- Require at least 2 occurrences to surface pattern
ORDER BY
    CASE
        WHEN fast_approval_count >= 5 AND total_fast_approved_spend >= 50000 THEN 1
        WHEN fast_approval_count >= 3 THEN 2
        ELSE 3
    END,
    total_fast_approved_spend DESC;
