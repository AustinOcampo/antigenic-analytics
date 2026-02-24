-- =============================================================================
-- ANTIGENIC ANALYTICS — SIGNAL: NEW VENDOR RAMP (ABNORMAL SPEND ACCELERATION)
-- =============================================================================
-- File:     new_vendor_ramp_detection.sql
-- Signal:   08 of 10 — Procurement & AP
-- Version:  1.0.0
-- License:  Apache 2.0
--
-- WHAT THIS DETECTS:
-- Newly onboarded vendors who reach high spend levels faster than is normal
-- for legitimate vendor relationships in that category. Legitimate vendors
-- earn trust over time through pilots, evaluations, and gradual scope expansion.
-- Fraudulent vendors — particularly those with insider sponsorship — skip this
-- ramp entirely because someone on the inside is pushing them through.
--
-- BEHAVIORAL TELL:
-- Speed is the tell. A legitimate vendor earns trust. A fraudulent vendor needs
-- to extract value before the relationship receives scrutiny. A vendor going
-- from $0 to $150,000 in spend within 60 days of onboarding, without a
-- corresponding purchase order trail, is not earning trust. They are racing.
--
-- DATA REQUIREMENTS:
-- Requires: vendor_id, vendor_name, invoice_amount, invoice_date,
--           vendor_onboard_date (date vendor was added to vendor master)
-- NOTE: If vendor_onboard_date is unavailable, the query uses the date of the
--       vendor's first invoice as a proxy. This is less precise but functional.
--
-- TUNING PARAMETERS:
-- * ramp_window_days         — days post-onboarding to measure ramp (default: 90)
-- * ramp_spend_threshold     — spend within ramp window to flag (default: $50,000)
-- * ramp_percentile_flag     — flag vendors above this percentile of ramp spend (default: 90th)
-- * min_comparable_vendors   — minimum peers needed for percentile comparison (default: 10)
--
-- TYPICAL EXPOSURE RANGE: $50,000 — $500,000
-- =============================================================================


-- =============================================================================
-- STEP 1: MAP YOUR COLUMNS AND SET YOUR THRESHOLDS
-- =============================================================================

WITH normalized_ledger AS (

    SELECT
        vendor_id               AS vendor_id,               -- expected: VARCHAR
        vendor_name             AS vendor_name,             -- expected: VARCHAR
        invoice_amount          AS invoice_amount,          -- expected: FLOAT
        invoice_date            AS invoice_date,            -- expected: DATE
        cost_center_id          AS cost_center_id,          -- expected: VARCHAR
        category_description    AS category_description,    -- expected: VARCHAR
        -- Vendor onboard date: use vendor master field if available
        -- If not available: use MIN(invoice_date) per vendor (fallback)
        vendor_created_date     AS vendor_onboard_date      -- expected: DATE (NULL ok — fallback below)

    FROM your_internal_table_name   -- << CHANGE THIS

    WHERE
        invoice_date >= DATEADD('year', -2, CURRENT_DATE)
        AND payment_status NOT IN ('VOIDED', 'CANCELLED')

),

thresholds AS (
    SELECT
        90      AS ramp_window_days,            -- Days post-onboarding that define "ramp period"
        50000   AS ramp_spend_threshold,        -- Minimum ramp spend to flag
        90      AS ramp_percentile_flag,        -- Flag vendors above this percentile
        10      AS min_comparable_vendors       -- Minimum peers for percentile to be meaningful
),


-- =============================================================================
-- STEP 2: ANTIGENIC ANALYTICS DETECTION LOGIC
-- =============================================================================

-- Determine effective onboard date per vendor
-- Uses vendor_onboard_date if available; falls back to first invoice date
vendor_onboard AS (
    SELECT
        vendor_id,
        vendor_name,
        category_description,
        COALESCE(
            MIN(vendor_onboard_date),
            MIN(invoice_date)           -- fallback: first invoice seen
        )                                               AS effective_onboard_date
    FROM normalized_ledger
    GROUP BY 1, 2, 3
),

-- Compute ramp spend: total spend within N days of onboarding
ramp_spend AS (
    SELECT
        l.vendor_id,
        l.vendor_name,
        l.category_description,
        o.effective_onboard_date,
        t.ramp_window_days,
        t.ramp_spend_threshold,
        t.ramp_percentile_flag,
        t.min_comparable_vendors,
        SUM(l.invoice_amount)                           AS ramp_period_spend,
        COUNT(DISTINCT l.invoice_date)                  AS active_billing_days_in_ramp,
        COUNT(*)                                        AS invoice_count_in_ramp,
        MAX(l.invoice_date)                             AS last_invoice_in_ramp,
        MAX(l.cost_center_id)                           AS primary_cost_center
    FROM normalized_ledger l
    JOIN vendor_onboard o ON l.vendor_id = o.vendor_id
    CROSS JOIN thresholds t
    WHERE
        l.invoice_date BETWEEN o.effective_onboard_date
                            AND DATEADD('day', t.ramp_window_days, o.effective_onboard_date)
    GROUP BY 1, 2, 3, 4, 5, 6, 7, 8
),

-- Category-level ramp benchmark: what's a normal ramp for this category?
category_ramp_benchmark AS (
    SELECT
        category_description,
        COUNT(DISTINCT vendor_id)                       AS vendor_count,
        AVG(ramp_period_spend)                          AS avg_category_ramp_spend,
        PERCENTILE_CONT(0.50) WITHIN GROUP (ORDER BY ramp_period_spend)
                                                        AS median_ramp_spend,
        PERCENTILE_CONT(0.90) WITHIN GROUP (ORDER BY ramp_period_spend)
                                                        AS p90_ramp_spend
    FROM ramp_spend
    GROUP BY 1
),

-- Compare each vendor's ramp to category benchmark
ramp_comparison AS (
    SELECT
        r.*,
        b.avg_category_ramp_spend,
        b.median_ramp_spend,
        b.p90_ramp_spend                                AS category_p90_ramp,
        b.vendor_count                                  AS comparable_vendors_in_category,
        ROUND(r.ramp_period_spend / NULLIF(b.avg_category_ramp_spend, 0), 2)
                                                        AS multiple_vs_category_avg,
        ROUND(r.ramp_period_spend / NULLIF(b.median_ramp_spend, 0), 2)
                                                        AS multiple_vs_category_median
    FROM ramp_spend r
    JOIN category_ramp_benchmark b ON r.category_description = b.category_description
)


-- =============================================================================
-- FINAL OUTPUT — GLASS BOX VERDICT
-- =============================================================================

SELECT
    vendor_id,
    vendor_name,
    category_description,
    primary_cost_center,
    effective_onboard_date,

    -- RAMP METRICS
    ramp_window_days,
    ramp_period_spend,
    invoice_count_in_ramp,
    active_billing_days_in_ramp,
    avg_category_ramp_spend                                 AS category_average_ramp_spend,
    category_p90_ramp                                       AS category_p90_ramp_spend,
    multiple_vs_category_avg,
    multiple_vs_category_median,

    -- CONFIDENCE
    CASE
        WHEN ramp_period_spend >= category_p90_ramp
         AND multiple_vs_category_avg >= 3.0               THEN 'HIGH — Top Decile + 3x Average'
        WHEN ramp_period_spend >= category_p90_ramp         THEN 'MEDIUM — Top Decile Ramp'
        WHEN multiple_vs_category_avg >= 2.5                THEN 'MEDIUM — 2.5x Category Average'
        ELSE 'LOW'
    END                                                     AS signal_confidence,

    'New Vendor Ramp'                                       AS signal_name,
    vendor_name || ' accumulated $'
        || ROUND(ramp_period_spend, 0)::VARCHAR
        || ' in spend within ' || ramp_window_days::VARCHAR
        || ' days of onboarding (' || invoice_count_in_ramp::VARCHAR
        || ' invoices). Category average ramp is $'
        || ROUND(avg_category_ramp_spend, 0)::VARCHAR
        || '. This vendor is ' || multiple_vs_category_avg::VARCHAR
        || 'x the category average.'                        AS glass_box_verdict

FROM ramp_comparison
WHERE
    ramp_period_spend >= ramp_spend_threshold
    AND (
        ramp_period_spend >= category_p90_ramp
        OR multiple_vs_category_avg >= 2.5
    )
    AND comparable_vendors_in_category >= min_comparable_vendors

ORDER BY
    CASE
        WHEN ramp_period_spend >= category_p90_ramp AND multiple_vs_category_avg >= 3.0 THEN 1
        WHEN ramp_period_spend >= category_p90_ramp THEN 2
        ELSE 3
    END,
    ramp_period_spend DESC;
