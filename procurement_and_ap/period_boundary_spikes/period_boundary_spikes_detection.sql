-- =============================================================================
-- ANTIGENIC ANALYTICS — SIGNAL: PERIOD BOUNDARY SPIKES
-- =============================================================================
-- File:     period_boundary_spikes_detection.sql
-- Signal:   05 of 10 — Procurement & AP
-- Version:  1.0.0
-- License:  Apache 2.0
--
-- WHAT THIS DETECTS:
-- Abnormal transaction volume or dollar value concentrated in the final days
-- of fiscal periods — month-end, quarter-end, or year-end — relative to that
-- vendor's normal mid-period activity. Fraudulent vendors time their largest
-- or most unusual invoices to exploit review fatigue at period close.
--
-- BEHAVIORAL TELL:
-- A vendor who bills evenly throughout the year suddenly submitting 40% of
-- their annual invoices in the last two weeks of Q4 is not doing that because
-- their work accelerated. They are timing submissions to exploit the window
-- when AP teams are overwhelmed and scrutiny is lowest.
--
-- DATA REQUIREMENTS:
-- Requires: vendor_id, vendor_name, invoice_amount, invoice_date, cost_center_id
--
-- TUNING PARAMETERS:
-- * period_boundary_days     — how many days at period end define the boundary window (default: 7)
-- * boundary_spend_ratio     — boundary spend / total monthly spend to flag (default: 0.40)
-- * min_vendor_months        — minimum months of history required (default: 6)
-- * min_boundary_amount      — minimum dollar amount in boundary window to flag (default: $10,000)
--
-- TYPICAL EXPOSURE RANGE: $50,000 — $750,000
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
        cost_center_id          AS cost_center_id           -- expected: VARCHAR

    FROM your_internal_table_name   -- << CHANGE THIS

    WHERE
        invoice_date >= DATEADD('year', -2, CURRENT_DATE)
        AND payment_status NOT IN ('VOIDED', 'CANCELLED')

),

thresholds AS (
    SELECT
        7       AS period_boundary_days,        -- Days at month-end that define the boundary window
        0.40    AS boundary_spend_ratio,        -- Flag if boundary spend > 40% of monthly total
        6       AS min_vendor_months,           -- Minimum months of history to establish baseline
        10000   AS min_boundary_amount          -- Minimum boundary spend to surface a finding
),


-- =============================================================================
-- STEP 2: ANTIGENIC ANALYTICS DETECTION LOGIC
-- =============================================================================

-- Tag each invoice as boundary or non-boundary
-- Boundary = within the last N days of the calendar month
invoices_tagged AS (
    SELECT
        vendor_id,
        vendor_name,
        invoice_amount,
        invoice_date,
        cost_center_id,
        DATE_TRUNC('month', invoice_date)       AS fiscal_month,
        LAST_DAY(invoice_date)                  AS month_end_date,
        DATEDIFF('day', invoice_date, LAST_DAY(invoice_date))
                                                AS days_before_month_end,
        t.period_boundary_days,
        t.boundary_spend_ratio,
        t.min_vendor_months,
        t.min_boundary_amount,
        CASE
            WHEN DATEDIFF('day', invoice_date, LAST_DAY(invoice_date))
                 < t.period_boundary_days       THEN 1
            ELSE 0
        END                                     AS is_boundary_invoice
    FROM normalized_ledger
    CROSS JOIN thresholds t
),

-- Monthly summary per vendor
monthly_summary AS (
    SELECT
        vendor_id,
        vendor_name,
        cost_center_id,
        fiscal_month,
        period_boundary_days,
        boundary_spend_ratio,
        min_vendor_months,
        min_boundary_amount,
        SUM(invoice_amount)                     AS total_monthly_spend,
        SUM(CASE WHEN is_boundary_invoice = 1
                 THEN invoice_amount ELSE 0 END) AS boundary_spend,
        SUM(CASE WHEN is_boundary_invoice = 0
                 THEN invoice_amount ELSE 0 END) AS mid_period_spend,
        COUNT(*)                                AS total_invoice_count,
        SUM(is_boundary_invoice)                AS boundary_invoice_count,
        ROUND(
            100.0 * SUM(CASE WHEN is_boundary_invoice = 1 THEN invoice_amount ELSE 0 END)
            / NULLIF(SUM(invoice_amount), 0), 2
        )                                       AS boundary_spend_pct
    FROM invoices_tagged
    GROUP BY 1, 2, 3, 4, 5, 6, 7, 8
),

-- Vendor history: how many months do we have data for?
vendor_history AS (
    SELECT
        vendor_id,
        COUNT(DISTINCT fiscal_month)            AS months_with_activity,
        AVG(boundary_spend_pct)                 AS avg_boundary_spend_pct,
        STDDEV(boundary_spend_pct)              AS stddev_boundary_spend_pct
    FROM monthly_summary
    GROUP BY 1
),

-- Flag months where boundary spend is anomalous vs this vendor's own baseline
flagged_months AS (
    SELECT
        m.*,
        h.months_with_activity,
        h.avg_boundary_spend_pct                AS vendor_avg_boundary_pct,
        h.stddev_boundary_spend_pct,
        -- Z-score: how many standard deviations above this vendor's own average?
        ROUND(
            (m.boundary_spend_pct - h.avg_boundary_spend_pct)
            / NULLIF(h.stddev_boundary_spend_pct, 0)
        , 2)                                    AS boundary_z_score,
        CASE
            WHEN m.boundary_spend_pct >= m.boundary_spend_ratio * 100
             AND (m.boundary_spend_pct - h.avg_boundary_spend_pct)
                 / NULLIF(h.stddev_boundary_spend_pct, 0) >= 2.0
                                                THEN 'HIGH — Spike + Anomaly vs Baseline'
            WHEN m.boundary_spend_pct >= m.boundary_spend_ratio * 100
                                                THEN 'MEDIUM — High Boundary Concentration'
            ELSE 'LOW'
        END                                     AS signal_confidence
    FROM monthly_summary m
    JOIN vendor_history h ON m.vendor_id = h.vendor_id
    WHERE
        h.months_with_activity >= m.min_vendor_months
        AND m.boundary_spend >= m.min_boundary_amount
        AND m.boundary_spend_pct >= m.boundary_spend_ratio * 100
)


-- =============================================================================
-- FINAL OUTPUT — GLASS BOX VERDICT
-- =============================================================================

SELECT
    vendor_id,
    vendor_name,
    cost_center_id,
    fiscal_month,

    -- SPIKE METRICS
    total_monthly_spend,
    boundary_spend,
    mid_period_spend,
    boundary_spend_pct                                      AS pct_spend_in_boundary_window,
    vendor_avg_boundary_pct                                 AS vendors_normal_boundary_pct,
    boundary_z_score,
    boundary_invoice_count,
    total_invoice_count,
    period_boundary_days                                    AS boundary_window_days,

    -- VERDICT
    signal_confidence,
    'Period Boundary Spikes'                                AS signal_name,
    vendor_name || ' concentrated ' || boundary_spend_pct::VARCHAR
        || '% of their ' || TO_CHAR(fiscal_month, 'Mon YYYY')
        || ' spend ($' || ROUND(boundary_spend, 0)::VARCHAR
        || ') into the final ' || period_boundary_days::VARCHAR
        || ' days of the month. This vendor''s normal boundary concentration is '
        || ROUND(vendor_avg_boundary_pct, 1)::VARCHAR
        || '%. Current month is ' || boundary_z_score::VARCHAR
        || ' standard deviations above their own baseline.'
                                                            AS glass_box_verdict

FROM flagged_months
ORDER BY signal_confidence, boundary_spend_pct DESC;
