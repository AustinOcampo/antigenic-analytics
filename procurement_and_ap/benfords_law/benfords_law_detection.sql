-- =============================================================================
-- ANTIGENIC ANALYTICS — SIGNAL: BENFORD'S LAW DEVIATION
-- =============================================================================
-- File:     benfords_law_detection.sql
-- Signal:   10 of 10 — Procurement & AP
-- Version:  1.0.0
-- License:  Apache 2.0
--
-- WHAT THIS DETECTS:
-- Populations of invoices whose leading-digit distribution deviates
-- significantly from Benford's Law — the statistical expectation that in
-- naturally occurring financial data, 1 appears first ~30% of the time,
-- declining logarithmically to 9 at ~5%. When numbers are fabricated,
-- humans instinctively distribute them more evenly, which is detectable.
--
-- BEHAVIORAL TELL:
-- Humans are bad at generating random numbers. Fabricated invoice amounts
-- cluster around psychologically comfortable numbers — lots of figures
-- starting with 5, 6, 7, avoiding numbers that feel too round or too precise.
-- Benford's Law catches this instinct at the population level.
--
-- IMPORTANT — HOW TO USE THIS SIGNAL CORRECTLY:
-- This is a SCOPING signal, not a transaction-level signal.
-- It does NOT tell you which specific invoices are fraudulent.
-- It tells you WHICH VENDOR or COST CENTER has a suspicious population —
-- then you investigate everything in that population using Signals 01–09.
--
-- EXCLUSIONS (CRITICAL — apply before running):
-- Benford's Law does NOT apply to:
--   * Fixed-fee or subscription billing (amounts are contractually set)
--   * Payroll (uniform amounts expected)
--   * Tax or regulatory payments (fixed rates)
--   * Populations with fewer than 100 invoices (insufficient sample size)
-- The query includes filters to exclude these populations automatically.
-- Review the exclusion logic in Step 1 and adjust for your data.
--
-- TUNING PARAMETERS:
-- * mad_flag_threshold       — Mean Absolute Deviation above which to flag (default: 0.015)
-- * min_invoice_count        — Minimum invoices for Benford's to be valid (default: 100)
-- * max_fixed_fee_pct        — Exclude populations where X% of amounts repeat (default: 30%)
--
-- TYPICAL USE: Flags populations for investigation — dollar quantification
-- comes from the companion signals run on the flagged population.
-- =============================================================================


-- =============================================================================
-- STEP 1: MAP YOUR COLUMNS AND SET YOUR THRESHOLDS
-- =============================================================================

WITH normalized_ledger AS (

    SELECT
        vendor_id               AS vendor_id,               -- expected: VARCHAR
        vendor_name             AS vendor_name,             -- expected: VARCHAR
        invoice_amount          AS invoice_amount,          -- expected: FLOAT (positive values)
        invoice_date            AS invoice_date,            -- expected: DATE
        cost_center_id          AS cost_center_id,          -- expected: VARCHAR
        approved_by_user_id     AS approved_by,             -- expected: VARCHAR
        category_description    AS category_description     -- expected: VARCHAR

    FROM your_internal_table_name   -- << CHANGE THIS

    WHERE
        invoice_date >= DATEADD('year', -2, CURRENT_DATE)
        AND payment_status NOT IN ('VOIDED', 'CANCELLED')
        AND invoice_amount > 0
        -- EXCLUSION: Remove payroll and tax categories
        -- Adjust these values to match your GL / category naming conventions
        AND LOWER(category_description) NOT LIKE '%payroll%'
        AND LOWER(category_description) NOT LIKE '%salary%'
        AND LOWER(category_description) NOT LIKE '%tax%'
        AND LOWER(category_description) NOT LIKE '%subscription%'

),

thresholds AS (
    SELECT
        0.015   AS mad_flag_threshold,          -- Mean Absolute Deviation threshold
        100     AS min_invoice_count,           -- Minimum invoices for valid Benford's analysis
        30.0    AS max_fixed_fee_pct            -- Exclude if >30% of amounts repeat (fixed-fee proxy)
),

-- Benford's expected distribution (immutable — do not edit)
benfords_expected AS (
    SELECT 1 AS leading_digit, 0.30103 AS expected_proportion UNION ALL
    SELECT 2, 0.17609 UNION ALL
    SELECT 3, 0.12494 UNION ALL
    SELECT 4, 0.09691 UNION ALL
    SELECT 5, 0.07918 UNION ALL
    SELECT 6, 0.06695 UNION ALL
    SELECT 7, 0.05799 UNION ALL
    SELECT 8, 0.05115 UNION ALL
    SELECT 9, 0.04576
),


-- =============================================================================
-- STEP 2: ANTIGENIC ANALYTICS DETECTION LOGIC
-- =============================================================================

-- Extract leading digit from each invoice amount
invoices_with_leading_digit AS (
    SELECT
        vendor_id,
        vendor_name,
        cost_center_id,
        category_description,
        approved_by,
        invoice_amount,
        -- Extract leading digit: convert to string, strip decimals, take first character
        CAST(LEFT(REGEXP_REPLACE(invoice_amount::VARCHAR, '^0+\\.?0*', ''), 1) AS INTEGER)
                                                AS leading_digit
    FROM normalized_ledger
    WHERE invoice_amount >= 1      -- Benford's requires amounts >= 1
),

-- Identify and flag fixed-fee populations (where many amounts repeat)
fixed_fee_check AS (
    SELECT
        vendor_id,
        COUNT(*)                                AS total_invoices,
        COUNT(DISTINCT invoice_amount)          AS distinct_amounts,
        ROUND(100.0 * (1.0 - COUNT(DISTINCT invoice_amount)::FLOAT / COUNT(*)), 1)
                                                AS repetition_pct
    FROM invoices_with_leading_digit
    GROUP BY 1
),

-- Vendor-level observed digit frequency
vendor_observed AS (
    SELECT
        l.vendor_id,
        l.vendor_name,
        l.leading_digit,
        COUNT(*)                                AS observed_count
    FROM invoices_with_leading_digit l
    JOIN fixed_fee_check f ON l.vendor_id = f.vendor_id
    CROSS JOIN thresholds t
    WHERE
        f.total_invoices >= t.min_invoice_count
        AND f.repetition_pct < t.max_fixed_fee_pct
        AND l.leading_digit BETWEEN 1 AND 9
    GROUP BY 1, 2, 3
),

-- Compute proportions and compare to Benford's expected
vendor_digit_comparison AS (
    SELECT
        o.vendor_id,
        o.vendor_name,
        o.leading_digit,
        o.observed_count,
        SUM(o.observed_count) OVER (PARTITION BY o.vendor_id)
                                                AS vendor_total_invoices,
        ROUND(o.observed_count::FLOAT / SUM(o.observed_count) OVER (PARTITION BY o.vendor_id), 5)
                                                AS observed_proportion,
        e.expected_proportion,
        ABS(
            o.observed_count::FLOAT / SUM(o.observed_count) OVER (PARTITION BY o.vendor_id)
            - e.expected_proportion
        )                                       AS absolute_deviation
    FROM vendor_observed o
    JOIN benfords_expected e ON o.leading_digit = e.leading_digit
),

-- Compute Mean Absolute Deviation (MAD) per vendor — the primary Benford's metric
vendor_mad AS (
    SELECT
        vendor_id,
        vendor_name,
        vendor_total_invoices,
        ROUND(AVG(absolute_deviation), 5)       AS mad_score,
        -- Collect digit-level detail for Glass Box output
        LISTAGG(
            'D' || leading_digit::VARCHAR || ': '
            || ROUND(observed_proportion * 100, 1)::VARCHAR || '% obs vs '
            || ROUND(expected_proportion * 100, 1)::VARCHAR || '% exp',
            ' | '
        ) WITHIN GROUP (ORDER BY leading_digit)  AS digit_distribution_detail
    FROM vendor_digit_comparison
    GROUP BY 1, 2, 3
),

-- Cost-center level analysis (second lens)
cost_center_observed AS (
    SELECT
        l.cost_center_id,
        l.leading_digit,
        COUNT(*)                                AS observed_count
    FROM invoices_with_leading_digit l
    JOIN fixed_fee_check f ON l.vendor_id = f.vendor_id
    CROSS JOIN thresholds t
    WHERE
        f.total_invoices >= t.min_invoice_count
        AND f.repetition_pct < t.max_fixed_fee_pct
        AND l.leading_digit BETWEEN 1 AND 9
    GROUP BY 1, 2
),

cost_center_mad AS (
    SELECT
        o.cost_center_id,
        SUM(o.observed_count)                   AS total_invoices,
        ROUND(AVG(ABS(
            o.observed_count::FLOAT / SUM(o.observed_count) OVER (PARTITION BY o.cost_center_id)
            - e.expected_proportion
        )), 5)                                  AS mad_score
    FROM cost_center_observed o
    JOIN benfords_expected e ON o.leading_digit = e.leading_digit
    GROUP BY 1
)


-- =============================================================================
-- FINAL OUTPUT — GLASS BOX VERDICT
-- =============================================================================

-- Vendor-level Benford's flags
SELECT
    vendor_id,
    vendor_name,
    NULL                                                    AS cost_center_id,
    'VENDOR'                                                AS analysis_level,
    vendor_total_invoices                                   AS invoices_analyzed,
    mad_score,
    digit_distribution_detail,

    CASE
        WHEN mad_score >= 0.025                             THEN 'HIGH — Severe Deviation'
        WHEN mad_score >= 0.015                             THEN 'MEDIUM — Moderate Deviation'
        ELSE 'LOW'
    END                                                     AS signal_confidence,

    'Benford''s Law Deviation'                              AS signal_name,

    vendor_name || ' shows a Benford''s Law MAD score of '
        || mad_score::VARCHAR
        || ' across ' || vendor_total_invoices::VARCHAR
        || ' invoices. Scores above 0.015 indicate non-organic number generation. '
        || 'Investigate this vendor population using Signals 01–09.'
                                                            AS glass_box_verdict

FROM vendor_mad
CROSS JOIN thresholds t
WHERE mad_score >= t.mad_flag_threshold

UNION ALL

-- Cost-center level Benford's flags
SELECT
    NULL,
    NULL,
    cost_center_id,
    'COST CENTER',
    total_invoices,
    mad_score,
    NULL,
    CASE
        WHEN mad_score >= 0.025                             THEN 'HIGH — Severe Deviation'
        WHEN mad_score >= 0.015                             THEN 'MEDIUM — Moderate Deviation'
        ELSE 'LOW'
    END,
    'Benford''s Law Deviation',
    'Cost center ' || cost_center_id
        || ' shows a Benford''s Law MAD score of ' || mad_score::VARCHAR
        || ' across ' || total_invoices::VARCHAR
        || ' invoices. Run Signal 01–09 across this entire cost center population.'

FROM cost_center_mad
CROSS JOIN thresholds t
WHERE mad_score >= t.mad_flag_threshold

ORDER BY signal_confidence, mad_score DESC;
