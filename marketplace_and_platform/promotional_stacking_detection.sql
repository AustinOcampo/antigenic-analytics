-- =============================================================================
-- ANTIGENIC ANALYTICS — SIGNAL: PROMOTIONAL STACKING EXPLOITATION
-- =============================================================================
-- File:     promotional_stacking_detection.sql
-- Signal:   M07 of 10 — Marketplace & Platform Fraud
-- Version:  1.0.0
-- License:  Apache 2.0
--
-- WHAT THIS DETECTS:
-- Buyers or sellers stacking multiple promotions in ways the platform never
-- intended to allow. Stacking exploits gaps between independent promotion
-- systems — combining a seller coupon with a platform-wide discount with a
-- referral credit with a first-purchase bonus — to purchase at or below cost.
-- Sophisticated stackers automate discovery of combinable offers and execute
-- at scale across multiple accounts.
--
-- BEHAVIORAL TELL:
-- Normal buyers occasionally benefit from overlapping promotions by chance.
-- Stackers show systematic patterns: every transaction uses the maximum
-- combinable discount, discount-to-order ratios far exceed platform averages,
-- and the same buyer (or fingerprint cluster) repeatedly finds and exploits
-- new promotion combinations within hours of launch.
--
-- DATA REQUIREMENTS:
-- Requires: transaction_id, buyer_id, transaction_amount, discount_amount,
--           transaction_timestamp, promo_codes_used
-- Optional: promo_code_type, buyer_device_id, buyer_ip_address,
--           buyer_account_created_at, original_list_price
--
-- TUNING PARAMETERS:
-- * min_transactions         — minimum transactions before flagging (default: 5)
-- * max_discount_rate_pct    — avg discount rate above which to flag (default: 40%)
-- * multi_promo_threshold    — transactions with 2+ promos to flag (default: 60%)
-- * lookback_days            — analysis window (default: 90)
--
-- TYPICAL EXPOSURE: $10K–$200K in eroded margin
-- =============================================================================


-- =============================================================================
-- STEP 1: MAP YOUR COLUMNS HERE
-- =============================================================================

WITH normalized_transactions AS (

    SELECT
        transaction_id          AS transaction_id,           -- expected: VARCHAR / STRING
        buyer_id                AS buyer_id,                 -- expected: VARCHAR / STRING
        amount                  AS transaction_amount,        -- expected: FLOAT / NUMBER (amount paid after discounts)
        discount_amount         AS discount_amount,          -- expected: FLOAT / NUMBER (total discount applied)
        created_at              AS transaction_timestamp,     -- expected: TIMESTAMP_NTZ
        promo_codes_applied     AS promo_codes_used,         -- expected: VARCHAR or ARRAY (comma-separated or array)
        device_id               AS buyer_device_id,          -- expected: VARCHAR
        ip_address              AS buyer_ip_address,         -- expected: VARCHAR

    FROM your_transaction_table                              -- << REPLACE WITH YOUR TABLE

),

normalized_buyers AS (

    SELECT
        buyer_id                AS buyer_id,                 -- expected: VARCHAR / STRING
        created_at              AS buyer_account_created_at,  -- expected: TIMESTAMP_NTZ

    FROM your_buyer_table                                    -- << REPLACE WITH YOUR TABLE

),


-- =============================================================================
-- STEP 2: THRESHOLDS
-- =============================================================================

thresholds AS (
    SELECT
        5       AS min_transactions,            -- need enough data to distinguish stackers from lucky buyers
        40.0    AS max_discount_rate_pct,       -- avg 40%+ discount rate = systematic exploitation
        60.0    AS multi_promo_threshold,       -- if 60%+ of transactions use multiple promos = intentional
        90      AS lookback_days
),


-- =============================================================================
-- DETECTION LOGIC — Do not alter below this line
-- =============================================================================

transactions_in_scope AS (
    SELECT
        *,
        transaction_amount + discount_amount                AS original_price,
        ROUND(100.0 * discount_amount
            / NULLIF(transaction_amount + discount_amount, 0), 1)
                                                            AS discount_rate_pct,
        -- Count promos per transaction (handles comma-separated or array)
        COALESCE(ARRAY_SIZE(TRY_PARSE_JSON(promo_codes_used)),
                 REGEXP_COUNT(promo_codes_used, ',') + 1,
                 0)                                         AS promo_count
    FROM normalized_transactions
    WHERE transaction_timestamp >= DATEADD('day', -1 * (SELECT lookback_days FROM thresholds), CURRENT_TIMESTAMP())
      AND discount_amount > 0
),

-- Step 1: Buyer-level stacking metrics
buyer_stacking_stats AS (
    SELECT
        t.buyer_id,
        COUNT(DISTINCT t.transaction_id)                    AS total_discounted_txns,
        SUM(t.discount_amount)                              AS total_discount_captured,
        SUM(t.transaction_amount)                           AS total_paid,
        SUM(t.original_price)                               AS total_original_price,
        ROUND(100.0 * SUM(t.discount_amount)
            / NULLIF(SUM(t.original_price), 0), 1)          AS avg_discount_rate_pct,
        -- Multi-promo usage
        COUNT(CASE WHEN t.promo_count >= 2 THEN 1 END)     AS multi_promo_txns,
        ROUND(100.0 * COUNT(CASE WHEN t.promo_count >= 2 THEN 1 END)
            / NULLIF(COUNT(*), 0), 1)                       AS multi_promo_pct,
        MAX(t.promo_count)                                  AS max_promos_single_txn,
        MAX(t.discount_rate_pct)                            AS max_discount_rate_pct,
        AVG(t.promo_count)                                  AS avg_promos_per_txn,
        -- Speed to new promos
        MIN(t.transaction_timestamp)                        AS first_discounted_txn,
        MAX(t.transaction_timestamp)                        AS last_discounted_txn,
        -- Account age at first stacking event
        DATEDIFF('day', b.buyer_account_created_at,
                 MIN(CASE WHEN t.promo_count >= 2 THEN t.transaction_timestamp END))
                                                            AS days_to_first_stack
    FROM transactions_in_scope t
    LEFT JOIN normalized_buyers b
        ON t.buyer_id = b.buyer_id
    GROUP BY t.buyer_id, b.buyer_account_created_at
),

-- Step 2: Platform baseline for comparison
platform_baseline AS (
    SELECT
        ROUND(AVG(discount_rate_pct), 1)                    AS platform_avg_discount_rate,
        ROUND(100.0 * COUNT(CASE WHEN promo_count >= 2 THEN 1 END)
            / NULLIF(COUNT(*), 0), 1)                       AS platform_multi_promo_rate
    FROM transactions_in_scope
),

-- Step 3: Score and flag
flagged_buyers AS (
    SELECT
        bss.*,
        pb.platform_avg_discount_rate,
        pb.platform_multi_promo_rate,
        bss.avg_discount_rate_pct - pb.platform_avg_discount_rate
                                                            AS discount_rate_elevation,
        CASE
            WHEN bss.avg_discount_rate_pct >= 60
             AND bss.multi_promo_pct >= 80
             AND bss.total_discounted_txns >= 10            THEN 'HIGH — Professional Stacking Operation'
            WHEN bss.avg_discount_rate_pct >= (SELECT max_discount_rate_pct FROM thresholds)
             AND bss.multi_promo_pct >= (SELECT multi_promo_threshold FROM thresholds)
                                                            THEN 'HIGH — Systematic Multi-Promo Abuse'
            WHEN bss.max_promos_single_txn >= 4             THEN 'MEDIUM — Extreme Single-Transaction Stacking'
            WHEN bss.multi_promo_pct >= (SELECT multi_promo_threshold FROM thresholds)
             AND bss.total_discount_captured >= 500         THEN 'MEDIUM — Persistent Multi-Promo Pattern'
            ELSE 'LOW'
        END                                                 AS signal_confidence
    FROM buyer_stacking_stats bss
    CROSS JOIN platform_baseline pb
    CROSS JOIN thresholds t
    WHERE bss.total_discounted_txns >= t.min_transactions
      AND (
          bss.avg_discount_rate_pct >= t.max_discount_rate_pct
          OR bss.multi_promo_pct >= t.multi_promo_threshold
      )
)


-- =============================================================================
-- FINAL OUTPUT — GLASS BOX VERDICT
-- =============================================================================

SELECT
    buyer_id,
    total_discounted_txns,
    total_discount_captured,
    total_paid,
    total_original_price,
    avg_discount_rate_pct,
    platform_avg_discount_rate,
    multi_promo_pct,
    max_promos_single_txn,
    avg_promos_per_txn,

    signal_confidence,
    'Promotional Stacking'                                  AS signal_name,
    'Buyer ' || buyer_id
        || ' captured $' || ROUND(total_discount_captured, 0)::VARCHAR
        || ' in discounts across ' || total_discounted_txns::VARCHAR
        || ' transactions. Avg discount rate: '
        || avg_discount_rate_pct::VARCHAR || '% (platform avg: '
        || platform_avg_discount_rate::VARCHAR || '%). '
        || multi_promo_pct::VARCHAR || '% of transactions used multiple promos. '
        || 'Max promos on single transaction: '
        || max_promos_single_txn::VARCHAR
        || '.'                                              AS glass_box_verdict

FROM flagged_buyers
ORDER BY signal_confidence, total_discount_captured DESC;
