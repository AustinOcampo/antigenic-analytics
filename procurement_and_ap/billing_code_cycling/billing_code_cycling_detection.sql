-- =============================================================================
-- ANTIGENIC ANALYTICS — SIGNAL: BILLING CODE CYCLING
-- =============================================================================
-- File:     billing_code_cycling_detection.sql
-- Signal:   03 of 10 — Procurement & AP
-- Version:  1.0.0
-- License:  Apache 2.0
--
-- WHAT THIS DETECTS:
-- A vendor rotating through billing codes in a pattern that suggests deliberate
-- evasion of frequency-based detection. Fraudulent vendors submit different
-- codes for the same underlying service to prevent any single code from
-- appearing anomalous — keeping each code's frequency artificially low while
-- maximizing total billing volume.
--
-- BEHAVIORAL TELL:
-- Natural billing has uneven code distribution — some codes appear constantly,
-- others rarely. Artificially cycled billing looks suspiciously balanced across
-- codes. Real human behavior isn't that tidy. A vendor whose top 5 billing codes
-- each appear almost exactly 20% of the time is not doing that organically.
--
-- DATA REQUIREMENTS:
-- Requires: vendor_id, vendor_name, billing_code, invoice_amount, invoice_date
-- Optional: category_description (improves peer group comparison)
--
-- TUNING PARAMETERS:
-- * min_invoices_to_analyze  — minimum invoices before running signal (default: 20)
-- * max_code_evenness_score  — higher = more even distribution = more suspicious
--                              (range 0–1, default flag at 0.80)
-- * min_unique_codes         — minimum distinct codes to flag cycling (default: 4)
-- * high_value_code_pct      — portion of codes that are above-average value (default: 60%)
--
-- TYPICAL EXPOSURE RANGE: $100,000 — $1,000,000+
-- =============================================================================


-- =============================================================================
-- STEP 1: MAP YOUR COLUMNS AND SET YOUR THRESHOLDS
-- =============================================================================

WITH normalized_ledger AS (

    SELECT
        vendor_id               AS vendor_id,               -- expected: VARCHAR
        vendor_name             AS vendor_name,             -- expected: VARCHAR
        billing_code            AS billing_code,            -- expected: VARCHAR
        invoice_amount          AS invoice_amount,          -- expected: FLOAT
        invoice_date            AS invoice_date,            -- expected: DATE
        category_description    AS category_description     -- expected: VARCHAR (NULL ok)

    FROM your_internal_table_name   -- << CHANGE THIS

    WHERE
        invoice_date >= DATEADD('year', -2, CURRENT_DATE)
        AND payment_status NOT IN ('VOIDED', 'CANCELLED')

),

thresholds AS (
    SELECT
        20      AS min_invoices_to_analyze,      -- Minimum invoices before signal fires
        0.80    AS max_code_evenness_score,      -- Evenness score above which we flag
        4       AS min_unique_codes,             -- Minimum distinct codes to indicate cycling
        60.0    AS high_value_code_pct           -- % of codes above avg value = high-value skew
),


-- =============================================================================
-- STEP 2: ANTIGENIC ANALYTICS DETECTION LOGIC
-- =============================================================================

-- Vendor-level billing code statistics
vendor_code_stats AS (
    SELECT
        vendor_id,
        vendor_name,
        billing_code,
        COUNT(*)                                AS code_frequency,
        SUM(invoice_amount)                     AS code_total_value,
        AVG(invoice_amount)                     AS code_avg_value,
        MIN(invoice_date)                       AS code_first_seen,
        MAX(invoice_date)                       AS code_last_seen
    FROM normalized_ledger
    GROUP BY 1, 2, 3
),

-- Vendor-level totals for share calculation
vendor_totals AS (
    SELECT
        vendor_id,
        SUM(code_frequency)                     AS total_invoices,
        SUM(code_total_value)                   AS total_vendor_spend,
        COUNT(DISTINCT billing_code)            AS unique_code_count,
        AVG(code_avg_value)                     AS vendor_avg_invoice_value
    FROM vendor_code_stats
    GROUP BY 1
),

-- Compute each code's frequency share and value share
code_shares AS (
    SELECT
        s.vendor_id,
        s.vendor_name,
        s.billing_code,
        s.code_frequency,
        s.code_total_value,
        s.code_avg_value,
        t.total_invoices,
        t.total_vendor_spend,
        t.unique_code_count,
        t.vendor_avg_invoice_value,
        ROUND(100.0 * s.code_frequency / NULLIF(t.total_invoices, 0), 2)
                                                AS frequency_share_pct,
        ROUND(100.0 * s.code_total_value / NULLIF(t.total_vendor_spend, 0), 2)
                                                AS value_share_pct,
        -- Is this code above the vendor's average invoice value?
        CASE WHEN s.code_avg_value > t.vendor_avg_invoice_value THEN 1 ELSE 0 END
                                                AS is_high_value_code
    FROM vendor_code_stats s
    JOIN vendor_totals t ON s.vendor_id = t.vendor_id
),

-- Measure evenness of code distribution using normalized entropy proxy
-- A perfectly even distribution (cycling) produces a score near 1.0
-- A natural skewed distribution produces a score near 0.0
vendor_evenness AS (
    SELECT
        vendor_id,
        vendor_name,
        total_invoices,
        total_vendor_spend,
        unique_code_count,
        vendor_avg_invoice_value,
        SUM(is_high_value_code)                 AS high_value_code_count,
        -- Evenness = 1 - (stddev of frequency shares / mean frequency share)
        -- Low stddev relative to mean = high evenness = suspicious
        ROUND(
            1.0 - (
                STDDEV(frequency_share_pct) / NULLIF(AVG(frequency_share_pct), 0)
            ) / unique_code_count
        , 4)                                    AS code_evenness_score,
        -- Collect all codes and their frequencies for the Glass Box output
        LISTAGG(
            billing_code || ': ' || code_frequency::VARCHAR || ' invoices ($'
            || ROUND(code_total_value, 0)::VARCHAR || ')',
            ' | '
        ) WITHIN GROUP (ORDER BY code_frequency DESC)
                                                AS code_distribution_log
    FROM code_shares
    GROUP BY 1, 2, 3, 4, 5, 6
),

-- Apply signal filters
flagged_vendors AS (
    SELECT
        v.*,
        t.max_code_evenness_score,
        t.high_value_code_pct,
        ROUND(100.0 * v.high_value_code_count / NULLIF(v.unique_code_count, 0), 1)
                                                AS pct_codes_above_avg_value,
        CASE
            WHEN v.code_evenness_score >= t.max_code_evenness_score
             AND (100.0 * v.high_value_code_count / NULLIF(v.unique_code_count, 0))
                 >= t.high_value_code_pct       THEN 'HIGH — Cycling + High Value Skew'
            WHEN v.code_evenness_score >= t.max_code_evenness_score
                                                THEN 'MEDIUM — Even Distribution'
            ELSE 'LOW'
        END                                     AS signal_confidence
    FROM vendor_evenness v
    CROSS JOIN thresholds t
    WHERE
        v.total_invoices >= t.min_invoices_to_analyze
        AND v.unique_code_count >= t.min_unique_codes
        AND v.code_evenness_score >= t.max_code_evenness_score
)


-- =============================================================================
-- FINAL OUTPUT — GLASS BOX VERDICT
-- =============================================================================

SELECT
    vendor_id,
    vendor_name,

    -- CYCLING METRICS
    unique_code_count                                       AS distinct_billing_codes_used,
    total_invoices                                          AS total_invoices_analyzed,
    total_vendor_spend                                      AS total_vendor_spend,
    code_evenness_score                                     AS distribution_evenness_score,
    pct_codes_above_avg_value                               AS pct_high_value_codes,
    code_distribution_log                                   AS billing_code_breakdown,

    -- VERDICT
    signal_confidence,
    'Billing Code Cycling'                                  AS signal_name,
    vendor_name || ' used ' || unique_code_count::VARCHAR
        || ' distinct billing codes across ' || total_invoices::VARCHAR
        || ' invoices. Distribution evenness score: ' || code_evenness_score::VARCHAR
        || ' (threshold: ' || max_code_evenness_score::VARCHAR
        || '). ' || pct_codes_above_avg_value::VARCHAR
        || '% of codes are above-average value, suggesting deliberate '
        || 'high-value code rotation.'                      AS glass_box_verdict

FROM flagged_vendors
ORDER BY signal_confidence, code_evenness_score DESC;
