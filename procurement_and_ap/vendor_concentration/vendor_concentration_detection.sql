-- =============================================================================
-- ANTIGENIC ANALYTICS — SIGNAL: VENDOR CONCENTRATION RATIO
-- =============================================================================
-- File:     vendor_concentration_detection.sql
-- Signal:   01 of 10 — Procurement & AP
-- Version:  1.0.0
-- License:  Apache 2.0
--
-- WHAT THIS DETECTS:
-- A single vendor capturing a disproportionate share of spend within a
-- category or cost center, relative to what is statistically normal.
-- Flags vendors whose concentration has GROWN over time — not just vendors
-- who are large. The trend is the signal, not the snapshot.
--
-- BEHAVIORAL TELL:
-- Fraudulent vendors don't just take a lot — they grow their take. A vendor
-- expanding from 15% to 60% of a category budget over 18 months without a
-- corresponding change in headcount, scope, or contract value is the pattern.
--
-- DATA REQUIREMENTS:
-- Requires: vendor_id, vendor_name, invoice_amount, invoice_date,
--           cost_center_id, category_description
--
-- TUNING PARAMETERS:
-- * concentration_flag_pct   — share % above which a vendor is flagged (default: 50%)
-- * growth_flag_pct          — share growth that triggers the trend signal (default: 20pp)
-- * min_vendor_count         — minimum vendors in category to run signal (default: 3)
-- * min_category_spend       — minimum category spend to run signal (default: $50,000)
--
-- TYPICAL EXPOSURE RANGE: $50,000 — $2,000,000
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
        category_description    AS category_description     -- expected: VARCHAR

    FROM your_internal_table_name   -- << CHANGE THIS

    WHERE
        invoice_date >= DATEADD('year', -2, CURRENT_DATE)
        AND payment_status NOT IN ('VOIDED', 'CANCELLED')

),

thresholds AS (
    SELECT
        50.0    AS concentration_flag_pct,      -- Flag if vendor holds >50% of category spend
        20.0    AS growth_flag_pct,             -- Flag if share grew >20 percentage points YoY
        3       AS min_vendor_count,            -- Minimum vendors in category to be meaningful
        50000   AS min_category_spend           -- Minimum category total to avoid noise
),


-- =============================================================================
-- STEP 2: ANTIGENIC ANALYTICS DETECTION LOGIC
-- Do not edit below this line.
-- =============================================================================

-- Annual spend by vendor and category
annual_spend AS (
    SELECT
        vendor_id,
        vendor_name,
        cost_center_id,
        category_description,
        DATE_TRUNC('year', invoice_date)        AS fiscal_year,
        SUM(invoice_amount)                     AS vendor_category_spend
    FROM normalized_ledger
    GROUP BY 1, 2, 3, 4, 5
),

-- Total category spend per year (denominator for share calculation)
category_totals AS (
    SELECT
        cost_center_id,
        category_description,
        fiscal_year,
        SUM(vendor_category_spend)              AS total_category_spend,
        COUNT(DISTINCT vendor_id)               AS vendor_count_in_category
    FROM annual_spend
    GROUP BY 1, 2, 3
),

-- Compute each vendor's concentration share per year
vendor_share AS (
    SELECT
        a.vendor_id,
        a.vendor_name,
        a.cost_center_id,
        a.category_description,
        a.fiscal_year,
        a.vendor_category_spend,
        c.total_category_spend,
        c.vendor_count_in_category,
        ROUND(100.0 * a.vendor_category_spend
            / NULLIF(c.total_category_spend, 0), 2)     AS concentration_pct
    FROM annual_spend a
    JOIN category_totals c
        ON  a.cost_center_id        = c.cost_center_id
        AND a.category_description  = c.category_description
        AND a.fiscal_year           = c.fiscal_year
),

-- Compare current year share vs prior year share to find growers
share_with_prior AS (
    SELECT
        vendor_id,
        vendor_name,
        cost_center_id,
        category_description,
        fiscal_year,
        vendor_category_spend,
        total_category_spend,
        vendor_count_in_category,
        concentration_pct,
        LAG(concentration_pct) OVER (
            PARTITION BY vendor_id, cost_center_id, category_description
            ORDER BY fiscal_year
        )                                               AS prior_year_concentration_pct,
        LAG(vendor_category_spend) OVER (
            PARTITION BY vendor_id, cost_center_id, category_description
            ORDER BY fiscal_year
        )                                               AS prior_year_spend
    FROM vendor_share
),

-- Apply signal filters
flagged_vendors AS (
    SELECT
        s.*,
        t.concentration_flag_pct,
        t.growth_flag_pct,
        ROUND(s.concentration_pct - COALESCE(s.prior_year_concentration_pct, 0), 2)
                                                        AS share_growth_pp,
        ROUND(s.vendor_category_spend - COALESCE(s.prior_year_spend, 0), 2)
                                                        AS spend_growth_dollars,
        CASE
            WHEN s.concentration_pct >= t.concentration_flag_pct
             AND (s.concentration_pct - COALESCE(s.prior_year_concentration_pct, 0))
                 >= t.growth_flag_pct                   THEN 'HIGH — Concentration + Growth'
            WHEN s.concentration_pct >= t.concentration_flag_pct THEN 'MEDIUM — Concentration Only'
            WHEN (s.concentration_pct - COALESCE(s.prior_year_concentration_pct, 0))
                 >= t.growth_flag_pct                   THEN 'MEDIUM — Rapid Growth'
            ELSE 'LOW'
        END                                             AS signal_confidence
    FROM share_with_prior s
    CROSS JOIN thresholds t
    WHERE
        s.vendor_count_in_category >= t.min_vendor_count
        AND s.total_category_spend >= t.min_category_spend
        AND (
            s.concentration_pct >= t.concentration_flag_pct
            OR (s.concentration_pct - COALESCE(s.prior_year_concentration_pct, 0))
               >= t.growth_flag_pct
        )
        AND s.fiscal_year = DATE_TRUNC('year', CURRENT_DATE)   -- Current year only in output
)


-- =============================================================================
-- FINAL OUTPUT — GLASS BOX VERDICT
-- =============================================================================

SELECT
    vendor_id,
    vendor_name,
    cost_center_id,
    category_description,
    fiscal_year,

    -- CONCENTRATION METRICS
    vendor_category_spend                                   AS vendor_spend_this_year,
    total_category_spend                                    AS total_category_spend,
    concentration_pct                                       AS vendor_share_pct,
    prior_year_concentration_pct                            AS prior_year_share_pct,
    share_growth_pp                                         AS share_growth_percentage_points,
    spend_growth_dollars                                    AS spend_growth_vs_prior_year,
    vendor_count_in_category                                AS competing_vendors_in_category,

    -- VERDICT
    signal_confidence,
    'Vendor Concentration Ratio'                            AS signal_name,
    vendor_name || ' holds ' || concentration_pct::VARCHAR
        || '% of ' || category_description
        || ' spend in ' || cost_center_id
        || ' (up from ' || COALESCE(prior_year_concentration_pct::VARCHAR, 'N/A')
        || '% prior year). Share grew '
        || share_growth_pp::VARCHAR || ' percentage points YoY.'
                                                            AS glass_box_verdict

FROM flagged_vendors
ORDER BY signal_confidence, concentration_pct DESC;
