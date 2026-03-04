-- =============================================================================
-- ANTIGENIC ANALYTICS — SIGNAL: PROMO CODE STACKING
-- =============================================================================
-- File:     promo_code_stacking_detection.sql
-- Signal:   L11 of 13 — Loyalty, Rewards & Promotion Fraud
-- Version:  1.0.0
-- License:  Apache 2.0
--
-- WHAT THIS DETECTS:
-- Members combining multiple promotional codes, referral credits, and loyalty
-- discounts on single transactions in ways the program never intended to allow.
-- Stackers discover combinable offers through systematic testing — applying
-- every active code to every cart until they find combinations that reduce
-- prices below cost. The behavior is methodical, not lucky.
--
-- BEHAVIORAL TELL:
-- Normal members occasionally benefit from an overlapping promotion by chance.
-- Stackers show a manufacturing pattern: every transaction uses the maximum
-- possible discount, the discount-to-order ratio far exceeds program averages,
-- and the same member repeatedly finds exploitable combinations within hours
-- of new promotions launching. Their discount capture rate is 3-5x the
-- population average, and their order frequency spikes around promo launches.
--
-- DATA REQUIREMENTS:
-- Requires: member_id, transaction_id, transaction_amount, discount_amount,
--           promo_codes_applied, transaction_timestamp
-- Optional: promo_code_type, original_list_price, points_applied,
--           referral_credit_applied, loyalty_discount_applied
--
-- TUNING PARAMETERS:
-- * min_transactions         — minimum transactions before flagging (default: 5)
-- * max_avg_discount_pct     — avg discount rate above which to flag (default: 35%)
-- * multi_code_threshold     — % of transactions with 2+ codes to flag (default: 50%)
-- * min_total_discount       — minimum total discount captured to surface (default: $200)
-- * lookback_days            — analysis window (default: 180)
--
-- TYPICAL EXPOSURE: $10,000 — $150,000
-- =============================================================================


-- =============================================================================
-- STEP 1: MAP YOUR COLUMNS AND SET YOUR THRESHOLDS
-- =============================================================================

WITH normalized_transactions AS (

    SELECT
        member_id               AS member_id,               -- expected: VARCHAR
        transaction_id          AS transaction_id,           -- expected: VARCHAR
        order_amount            AS transaction_amount,       -- expected: FLOAT (amount paid after discounts)
        discount_total          AS discount_amount,          -- expected: FLOAT (total discount applied)
        promo_codes             AS promo_codes_applied,      -- expected: VARCHAR or ARRAY (comma-separated or array)
        points_redeemed_value   AS points_applied,           -- expected: FLOAT (dollar value of points used, 0 if none)
        referral_credit         AS referral_credit_applied,  -- expected: FLOAT (0 if none)
        loyalty_discount        AS loyalty_discount_applied, -- expected: FLOAT (0 if none)
        created_at              AS transaction_timestamp,    -- expected: TIMESTAMP_NTZ

    FROM your_transaction_table                              -- << REPLACE WITH YOUR TABLE

    WHERE created_at >= DATEADD('day', -180, CURRENT_TIMESTAMP())  -- << ADJUST LOOKBACK

),


-- =============================================================================
-- STEP 2: THRESHOLDS
-- =============================================================================

thresholds AS (
    SELECT
        5       AS min_transactions,            -- need enough volume to distinguish stackers from lucky buyers
        35.0    AS max_avg_discount_pct,        -- avg 35%+ discount rate = systematic exploitation
        50.0    AS multi_code_threshold,        -- if 50%+ of transactions use multiple promos = intentional
        200     AS min_total_discount            -- filter trivially small amounts
),


-- =============================================================================
-- DETECTION LOGIC — Do not alter below this line
-- =============================================================================

-- Compute per-transaction metrics
transaction_enriched AS (
    SELECT
        *,
        transaction_amount + discount_amount                AS original_price,
        ROUND(100.0 * discount_amount
            / NULLIF(transaction_amount + discount_amount, 0), 1)
                                                            AS discount_rate_pct,
        -- Count promo codes per transaction
        COALESCE(ARRAY_SIZE(TRY_PARSE_JSON(promo_codes_applied)),
                 REGEXP_COUNT(promo_codes_applied, ',') + 1,
                 0)                                         AS promo_code_count,
        -- Count total discount sources (promo + points + referral + loyalty)
        (CASE WHEN discount_amount > 0 THEN 1 ELSE 0 END
       + CASE WHEN COALESCE(points_applied, 0) > 0 THEN 1 ELSE 0 END
       + CASE WHEN COALESCE(referral_credit_applied, 0) > 0 THEN 1 ELSE 0 END
       + CASE WHEN COALESCE(loyalty_discount_applied, 0) > 0 THEN 1 ELSE 0 END
        )                                                   AS discount_source_count
    FROM normalized_transactions
    WHERE discount_amount > 0
),

-- Member-level stacking stats
member_stacking_stats AS (
    SELECT
        member_id,
        COUNT(DISTINCT transaction_id)                      AS total_discounted_txns,
        SUM(discount_amount)                                AS total_discount_captured,
        SUM(transaction_amount)                             AS total_paid,
        SUM(original_price)                                 AS total_original_price,
        ROUND(100.0 * SUM(discount_amount)
            / NULLIF(SUM(original_price), 0), 1)            AS avg_discount_rate_pct,
        -- Multi-code usage
        COUNT(CASE WHEN promo_code_count >= 2 THEN 1 END)  AS multi_code_txns,
        ROUND(100.0 * COUNT(CASE WHEN promo_code_count >= 2 THEN 1 END)
            / NULLIF(COUNT(*), 0), 1)                       AS multi_code_pct,
        -- Multi-source stacking (promo + points + referral + loyalty)
        COUNT(CASE WHEN discount_source_count >= 3 THEN 1 END)
                                                            AS triple_stack_txns,
        MAX(promo_code_count)                               AS max_codes_single_txn,
        MAX(discount_source_count)                          AS max_sources_single_txn,
        MAX(discount_rate_pct)                              AS max_discount_rate_pct,
        AVG(promo_code_count)                               AS avg_codes_per_txn,
        MIN(transaction_timestamp)                          AS first_stacked_txn,
        MAX(transaction_timestamp)                          AS last_stacked_txn
    FROM transaction_enriched
    GROUP BY member_id
),

-- Population baseline for comparison
population_baseline AS (
    SELECT
        ROUND(AVG(discount_rate_pct), 1)                    AS pop_avg_discount_rate,
        ROUND(100.0 * COUNT(CASE WHEN promo_code_count >= 2 THEN 1 END)
            / NULLIF(COUNT(*), 0), 1)                       AS pop_multi_code_rate,
        ROUND(AVG(promo_code_count), 2)                     AS pop_avg_codes_per_txn
    FROM transaction_enriched
),

-- Score and flag
flagged_members AS (
    SELECT
        mss.*,
        pb.pop_avg_discount_rate,
        pb.pop_multi_code_rate,
        pb.pop_avg_codes_per_txn,
        mss.avg_discount_rate_pct - pb.pop_avg_discount_rate
                                                            AS discount_rate_elevation,
        CASE
            WHEN mss.avg_discount_rate_pct >= 50
             AND mss.multi_code_pct >= 75
             AND mss.triple_stack_txns >= 3                  THEN 'HIGH — Professional Stacking Operation'
            WHEN mss.avg_discount_rate_pct >= (SELECT max_avg_discount_pct FROM thresholds)
             AND mss.multi_code_pct >= (SELECT multi_code_threshold FROM thresholds)
                                                            THEN 'HIGH — Systematic Multi-Code Abuse'
            WHEN mss.max_sources_single_txn >= 4             THEN 'MEDIUM — Extreme Single-Transaction Stacking'
            WHEN mss.multi_code_pct >= (SELECT multi_code_threshold FROM thresholds)
             AND mss.total_discount_captured >= 500          THEN 'MEDIUM — Persistent Multi-Code Pattern'
            ELSE 'LOW'
        END                                                 AS signal_confidence
    FROM member_stacking_stats mss
    CROSS JOIN population_baseline pb
    CROSS JOIN thresholds t
    WHERE mss.total_discounted_txns >= t.min_transactions
      AND mss.total_discount_captured >= t.min_total_discount
      AND (
          mss.avg_discount_rate_pct >= t.max_avg_discount_pct
          OR mss.multi_code_pct >= t.multi_code_threshold
      )
)


-- =============================================================================
-- FINAL OUTPUT — GLASS BOX VERDICT
-- =============================================================================

SELECT
    member_id,
    total_discounted_txns,
    total_discount_captured,
    total_paid,
    total_original_price,
    avg_discount_rate_pct,
    pop_avg_discount_rate,
    discount_rate_elevation,
    multi_code_pct,
    triple_stack_txns,
    max_codes_single_txn,
    max_sources_single_txn,
    avg_codes_per_txn,

    signal_confidence,
    'Promo Code Stacking'                                   AS signal_name,
    'Member ' || member_id
        || ' captured $' || ROUND(total_discount_captured, 0)::VARCHAR
        || ' in discounts across ' || total_discounted_txns::VARCHAR
        || ' transactions. Avg discount rate: '
        || avg_discount_rate_pct::VARCHAR || '% (population avg: '
        || pop_avg_discount_rate::VARCHAR || '%). '
        || multi_code_pct::VARCHAR || '% of transactions used multiple codes. '
        || 'Max codes on single transaction: ' || max_codes_single_txn::VARCHAR
        || '. Max discount sources stacked: ' || max_sources_single_txn::VARCHAR
        || '.'                                              AS glass_box_verdict

FROM flagged_members
ORDER BY signal_confidence, total_discount_captured DESC;
