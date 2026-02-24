-- =============================================================================
-- ANTIGENIC ANALYTICS — SIGNAL: DUPLICATE BILLING (MORPHED IDENTIFIERS)
-- =============================================================================
-- File:     duplicate_billing_detection.sql
-- Signal:   09 of 10 — Procurement & AP
-- Version:  1.0.0
-- License:  Apache 2.0
--
-- WHAT THIS DETECTS:
-- Invoices submitted multiple times with slight variations in identifiers —
-- invoice number, date, amount, or description — designed to evade exact-match
-- duplicate detection in AP systems. Legitimate billing errors are corrected
-- when flagged. Morphed duplicates are submitted proactively with deliberate
-- variation. That intent is what separates them, and the pattern reveals it.
--
-- BEHAVIORAL TELL:
-- An invoice for $9,800 submitted on April 3 and again on April 7 with a
-- slightly different invoice number is not a billing error. It is a calculated
-- submission designed to pass through automated duplicate checks. The variation
-- is the signature of deliberate morphing.
--
-- DETECTION APPROACH:
-- This signal uses fuzzy matching across four dimensions simultaneously:
-- 1. Same vendor
-- 2. Invoice amount within a tolerance band (±2%)
-- 3. Submission dates within a defined window (default: 45 days)
-- 4. Invoice number similarity (catches single-digit transpositions)
-- A pair that matches on all four dimensions is a high-confidence duplicate.
--
-- DATA REQUIREMENTS:
-- Requires: vendor_id, vendor_name, invoice_number, invoice_amount, invoice_date
-- Optional: cost_center_id, approved_by (improves investigative output)
--
-- TUNING PARAMETERS:
-- * amount_tolerance_pct     — % difference in amount still considered duplicate (default: 2%)
-- * date_window_days         — days between submissions still considered duplicate (default: 45)
-- * min_duplicate_amount     — minimum invoice amount to surface (default: $1,000)
--
-- NOTE ON RECOVERY:
-- Each confirmed duplicate is 100% recoverable — it represents money paid twice
-- for one service. No exposure estimation required. The dollar amount IS the loss.
--
-- TYPICAL EXPOSURE: 100% recoverable per confirmed pair
-- =============================================================================


-- =============================================================================
-- STEP 1: MAP YOUR COLUMNS AND SET YOUR THRESHOLDS
-- =============================================================================

WITH normalized_ledger AS (

    SELECT
        invoice_id              AS transaction_id,          -- expected: VARCHAR
        invoice_number          AS invoice_number,          -- expected: VARCHAR
        vendor_id               AS vendor_id,               -- expected: VARCHAR
        vendor_name             AS vendor_name,             -- expected: VARCHAR
        invoice_amount          AS invoice_amount,          -- expected: FLOAT
        invoice_date            AS invoice_date,            -- expected: DATE
        cost_center_id          AS cost_center_id,          -- expected: VARCHAR
        approved_by_user_id     AS approved_by,             -- expected: VARCHAR (NULL ok)
        payment_status          AS payment_status           -- expected: VARCHAR

    FROM your_internal_table_name   -- << CHANGE THIS

    WHERE
        invoice_date >= DATEADD('year', -2, CURRENT_DATE)
        AND payment_status NOT IN ('VOIDED', 'CANCELLED')

),

thresholds AS (
    SELECT
        2.0     AS amount_tolerance_pct,        -- Invoices within ±2% of each other are candidates
        45      AS date_window_days,            -- Maximum days between duplicate submissions
        1000    AS min_duplicate_amount         -- Minimum invoice amount to surface
),


-- =============================================================================
-- STEP 2: ANTIGENIC ANALYTICS DETECTION LOGIC
-- =============================================================================

-- Self-join invoices to find suspicious pairs
-- Conditions: same vendor, similar amount, close dates, different invoice number
candidate_pairs AS (
    SELECT
        a.transaction_id                        AS invoice_id_a,
        a.invoice_number                        AS invoice_number_a,
        a.invoice_amount                        AS invoice_amount_a,
        a.invoice_date                          AS invoice_date_a,
        a.cost_center_id                        AS cost_center_a,
        a.approved_by                           AS approved_by_a,
        a.payment_status                        AS payment_status_a,

        b.transaction_id                        AS invoice_id_b,
        b.invoice_number                        AS invoice_number_b,
        b.invoice_amount                        AS invoice_amount_b,
        b.invoice_date                          AS invoice_date_b,
        b.cost_center_id                        AS cost_center_b,
        b.approved_by                           AS approved_by_b,
        b.payment_status                        AS payment_status_b,

        a.vendor_id,
        a.vendor_name,
        t.amount_tolerance_pct,
        t.date_window_days,

        -- Amount difference
        ROUND(ABS(a.invoice_amount - b.invoice_amount), 2)
                                                AS amount_difference,
        ROUND(
            100.0 * ABS(a.invoice_amount - b.invoice_amount) / NULLIF(a.invoice_amount, 0)
        , 2)                                    AS amount_difference_pct,

        -- Date difference
        DATEDIFF('day', a.invoice_date, b.invoice_date)
                                                AS days_between_submissions,

        -- Invoice number similarity score
        -- Exact match on cleaned invoice numbers suggests same underlying invoice
        -- Near-match (1 char different) suggests deliberate morphing
        CASE
            WHEN LOWER(TRIM(a.invoice_number)) = LOWER(TRIM(b.invoice_number))
                                                THEN 'EXACT_MATCH'
            WHEN LEFT(LOWER(TRIM(a.invoice_number)), LEN(TRIM(a.invoice_number)) - 1)
               = LEFT(LOWER(TRIM(b.invoice_number)), LEN(TRIM(b.invoice_number)) - 1)
                                                THEN 'NEAR_MATCH_TRAILING'
            WHEN RIGHT(LOWER(TRIM(a.invoice_number)), LEN(TRIM(a.invoice_number)) - 1)
               = RIGHT(LOWER(TRIM(b.invoice_number)), LEN(TRIM(b.invoice_number)) - 1)
                                                THEN 'NEAR_MATCH_LEADING'
            ELSE 'DIFFERENT'
        END                                     AS invoice_number_similarity

    FROM normalized_ledger a
    JOIN normalized_ledger b
        ON  a.vendor_id = b.vendor_id
        AND a.transaction_id < b.transaction_id     -- prevent duplicate pairs and self-joins
        AND a.invoice_amount >= t.min_duplicate_amount
        AND ABS(a.invoice_amount - b.invoice_amount)
            <= (t.amount_tolerance_pct / 100.0) * a.invoice_amount
        AND DATEDIFF('day', a.invoice_date, b.invoice_date)
            BETWEEN 0 AND t.date_window_days
    CROSS JOIN thresholds t
),

-- Score and classify each candidate pair
scored_pairs AS (
    SELECT
        *,
        -- Count matching dimensions to compute confidence
        (CASE WHEN invoice_number_similarity IN ('EXACT_MATCH', 'NEAR_MATCH_TRAILING', 'NEAR_MATCH_LEADING')
              THEN 1 ELSE 0 END
        + CASE WHEN amount_difference_pct < 1.0  THEN 1 ELSE 0 END
        + CASE WHEN days_between_submissions <= 14 THEN 1 ELSE 0 END
        + CASE WHEN cost_center_a = cost_center_b  THEN 1 ELSE 0 END
        )                                       AS match_dimension_count,

        CASE
            WHEN invoice_number_similarity IN ('EXACT_MATCH', 'NEAR_MATCH_TRAILING', 'NEAR_MATCH_LEADING')
             AND amount_difference_pct < 1.0
             AND days_between_submissions <= 14  THEN 'HIGH — Near-Identical Across All Dimensions'
            WHEN invoice_number_similarity IN ('EXACT_MATCH', 'NEAR_MATCH_TRAILING', 'NEAR_MATCH_LEADING')
             AND amount_difference_pct < 2.0    THEN 'MEDIUM — Invoice Number + Amount Match'
            WHEN amount_difference_pct < 1.0
             AND days_between_submissions <= 7  THEN 'MEDIUM — Same Amount, Close Dates'
            ELSE 'LOW'
        END                                     AS signal_confidence,

        -- Duplicate exposure: the smaller of the two invoices
        -- (one is legitimate; the other is the duplicate)
        LEAST(invoice_amount_a, invoice_amount_b)
                                                AS recoverable_exposure

    FROM candidate_pairs
)


-- =============================================================================
-- FINAL OUTPUT — GLASS BOX VERDICT
-- =============================================================================

SELECT
    vendor_id,
    vendor_name,

    -- PAIR A
    invoice_id_a,
    invoice_number_a,
    invoice_amount_a,
    invoice_date_a,
    cost_center_a,
    approved_by_a,
    payment_status_a,

    -- PAIR B (the suspected duplicate)
    invoice_id_b,
    invoice_number_b,
    invoice_amount_b,
    invoice_date_b,
    cost_center_b,
    approved_by_b,
    payment_status_b,

    -- SIMILARITY METRICS
    amount_difference,
    amount_difference_pct,
    days_between_submissions,
    invoice_number_similarity,
    match_dimension_count,

    -- RECOVERY
    recoverable_exposure,

    -- VERDICT
    signal_confidence,
    'Duplicate Billing — Morphed Identifiers'           AS signal_name,
    vendor_name || ': Invoice ' || invoice_number_a
        || ' ($' || invoice_amount_a::VARCHAR || ', ' || invoice_date_a::VARCHAR || ')'
        || ' and Invoice ' || invoice_number_b
        || ' ($' || invoice_amount_b::VARCHAR || ', ' || invoice_date_b::VARCHAR || ')'
        || ' match on ' || match_dimension_count::VARCHAR || ' of 4 dimensions.'
        || ' Amount difference: ' || amount_difference_pct::VARCHAR
        || '%. Days between: ' || days_between_submissions::VARCHAR
        || '. Invoice number similarity: ' || invoice_number_similarity
        || '. Recoverable exposure: $' || ROUND(recoverable_exposure, 0)::VARCHAR
                                                        AS glass_box_verdict

FROM scored_pairs
WHERE signal_confidence IN ('HIGH — Near-Identical Across All Dimensions',
                            'MEDIUM — Invoice Number + Amount Match',
                            'MEDIUM — Same Amount, Close Dates')

ORDER BY
    CASE signal_confidence
        WHEN 'HIGH — Near-Identical Across All Dimensions' THEN 1
        WHEN 'MEDIUM — Invoice Number + Amount Match'      THEN 2
        ELSE 3
    END,
    recoverable_exposure DESC;
