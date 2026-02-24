-- =============================================================================
-- ANTIGENIC ANALYTICS — SIGNAL: SERVICE-TO-OUTCOME MISMATCH
-- =============================================================================
-- File:     service_outcome_mismatch_detection.sql
-- Signal:   06 of 10 — Procurement & AP
-- Version:  1.0.0
-- License:  Apache 2.0
--
-- WHAT THIS DETECTS:
-- A vendor billing for services at a volume or frequency inconsistent with
-- measurable operational proxies — headcount served, facility utilization,
-- project activity, or billing days. Fraudulent service vendors avoid
-- creating documentation trails and prefer vague scope descriptions
-- because there is no physical output to verify.
--
-- BEHAVIORAL TELL:
-- A staffing company billing for 200 hours in a department with 10 employees
-- during a month where that department reported no active projects has a math
-- problem. The billing volume is implausible given the operational context.
-- That implausibility is the signal.
--
-- DATA REQUIREMENTS:
-- Requires: vendor_id, vendor_name, invoice_amount, invoice_date, cost_center_id,
--           billed_units (hours, days, units — whatever the vendor invoices by)
-- Requires (operational proxy): headcount or capacity metric per cost center per month
--           This may require a JOIN to HR or facilities data.
-- NOTE: If operational proxy data is unavailable, the query falls back to
--       comparing billed units against this vendor's own historical average.
--       Fallback mode reduces precision but still surfaces outlier months.
--
-- TUNING PARAMETERS:
-- * hours_per_person_per_month   — max plausible billable hours per headcount (default: 160)
-- * unit_spike_multiplier        — flag if billed units > X times vendor's own average (default: 2.5x)
-- * min_months_for_baseline      — minimum months to establish vendor baseline (default: 4)
-- * min_flag_amount              — minimum invoice amount to surface (default: $5,000)
--
-- TYPICAL EXPOSURE RANGE: $75,000 — $1,000,000
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
        -- BILLED UNITS: Map to whatever unit this vendor invoices by
        -- Examples: billed_hours, billed_days, service_units, quantity
        billed_hours            AS billed_units,            -- expected: FLOAT (NULL ok — fallback activates)
        category_description    AS category_description     -- expected: VARCHAR

    FROM your_internal_table_name   -- << CHANGE THIS

    WHERE
        invoice_date >= DATEADD('year', -2, CURRENT_DATE)
        AND payment_status NOT IN ('VOIDED', 'CANCELLED')

),

-- OPERATIONAL PROXY TABLE (headcount or capacity per cost center per month)
-- If this data doesn't exist, comment out this CTE and the joins below.
-- The query will fall back to vendor's own historical average.
normalized_headcount AS (

    SELECT
        cost_center_id          AS cost_center_id,          -- expected: VARCHAR
        DATE_TRUNC('month', effective_date)
                                AS effective_month,         -- expected: DATE -> truncated to month
        headcount               AS headcount                -- expected: INTEGER

    FROM your_headcount_table   -- << CHANGE THIS (HR / workforce table)

),

thresholds AS (
    SELECT
        160     AS hours_per_person_per_month,  -- Max plausible billable hours per headcount
        2.5     AS unit_spike_multiplier,       -- Flag if billed units > 2.5x vendor's own avg
        4       AS min_months_for_baseline,     -- Minimum months to compute vendor baseline
        5000    AS min_flag_amount              -- Minimum invoice amount to surface
),


-- =============================================================================
-- STEP 2: ANTIGENIC ANALYTICS DETECTION LOGIC
-- =============================================================================

-- Monthly billed units per vendor per cost center
monthly_billing AS (
    SELECT
        vendor_id,
        vendor_name,
        cost_center_id,
        category_description,
        DATE_TRUNC('month', invoice_date)       AS billing_month,
        SUM(invoice_amount)                     AS monthly_spend,
        SUM(billed_units)                       AS monthly_billed_units,
        COUNT(*)                                AS invoice_count
    FROM normalized_ledger
    GROUP BY 1, 2, 3, 4, 5
),

-- Vendor baseline: average monthly billed units across all historical months
vendor_baseline AS (
    SELECT
        vendor_id,
        AVG(monthly_billed_units)               AS avg_monthly_units,
        STDDEV(monthly_billed_units)            AS stddev_monthly_units,
        COUNT(DISTINCT billing_month)           AS months_of_history
    FROM monthly_billing
    WHERE monthly_billed_units IS NOT NULL
    GROUP BY 1
),

-- Join to headcount proxy where available
billing_with_capacity AS (
    SELECT
        m.*,
        h.headcount                             AS cost_center_headcount,
        t.hours_per_person_per_month            AS hours_per_person,
        t.unit_spike_multiplier,
        t.min_months_for_baseline,
        t.min_flag_amount,
        -- Maximum plausible units given headcount
        h.headcount * t.hours_per_person_per_month
                                                AS capacity_ceiling,
        -- Vendor's own historical average
        vb.avg_monthly_units,
        vb.stddev_monthly_units,
        vb.months_of_history
    FROM monthly_billing m
    LEFT JOIN normalized_headcount h
        ON  m.cost_center_id = h.cost_center_id
        AND m.billing_month  = h.effective_month
    LEFT JOIN vendor_baseline vb ON m.vendor_id = vb.vendor_id
    CROSS JOIN thresholds t
),

-- Flag months where billed units exceed capacity or vendor's own spike threshold
flagged_months AS (
    SELECT
        *,
        -- Capacity-based excess (requires headcount data)
        CASE WHEN capacity_ceiling IS NOT NULL AND monthly_billed_units > capacity_ceiling
             THEN ROUND(monthly_billed_units - capacity_ceiling, 1)
             ELSE NULL
        END                                     AS units_above_capacity,
        -- Spike vs vendor baseline
        ROUND(monthly_billed_units / NULLIF(avg_monthly_units, 0), 2)
                                                AS units_vs_vendor_avg_multiple,
        CASE
            WHEN capacity_ceiling IS NOT NULL
             AND monthly_billed_units > capacity_ceiling
             AND monthly_billed_units > unit_spike_multiplier * avg_monthly_units
                                                THEN 'HIGH — Exceeds Capacity + Spike vs Baseline'
            WHEN capacity_ceiling IS NOT NULL
             AND monthly_billed_units > capacity_ceiling
                                                THEN 'HIGH — Exceeds Headcount Capacity'
            WHEN monthly_billed_units > unit_spike_multiplier * avg_monthly_units
             AND months_of_history >= min_months_for_baseline
                                                THEN 'MEDIUM — Spike vs Own Baseline'
            ELSE 'LOW'
        END                                     AS signal_confidence
    FROM billing_with_capacity
    WHERE
        monthly_spend >= min_flag_amount
        AND (
            (capacity_ceiling IS NOT NULL AND monthly_billed_units > capacity_ceiling)
            OR
            (months_of_history >= min_months_for_baseline
             AND monthly_billed_units > unit_spike_multiplier * avg_monthly_units)
        )
)


-- =============================================================================
-- FINAL OUTPUT — GLASS BOX VERDICT
-- =============================================================================

SELECT
    vendor_id,
    vendor_name,
    cost_center_id,
    category_description,
    billing_month,

    -- MISMATCH METRICS
    monthly_spend,
    monthly_billed_units                                    AS billed_units_this_month,
    capacity_ceiling                                        AS max_plausible_units_by_headcount,
    units_above_capacity,
    avg_monthly_units                                       AS vendor_historical_avg_units,
    units_vs_vendor_avg_multiple                            AS multiple_vs_own_average,
    cost_center_headcount,

    -- VERDICT
    signal_confidence,
    'Service-to-Outcome Mismatch'                           AS signal_name,
    vendor_name || ' billed ' || monthly_billed_units::VARCHAR
        || ' units in ' || TO_CHAR(billing_month, 'Mon YYYY')
        || ' ($' || ROUND(monthly_spend, 0)::VARCHAR || '). '
        || COALESCE(
            'Headcount capacity ceiling: ' || ROUND(capacity_ceiling, 0)::VARCHAR || ' units. ',
            ''
        )
        || 'Vendor''s own monthly average: ' || ROUND(avg_monthly_units, 1)::VARCHAR
        || ' units. Current month is ' || units_vs_vendor_avg_multiple::VARCHAR
        || 'x their historical baseline.'                   AS glass_box_verdict

FROM flagged_months
ORDER BY signal_confidence, monthly_spend DESC;
