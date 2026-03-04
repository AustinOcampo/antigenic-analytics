-- =============================================================================
-- ANTIGENIC ANALYTICS — SIGNAL: BUYER-SELLER COORDINATION PATTERNS
-- =============================================================================
-- File:     buyer_seller_coordination_detection.sql
-- Signal:   M09 of 10 — Marketplace & Platform Fraud
-- Version:  1.0.0
-- License:  Apache 2.0
--
-- WHAT THIS DETECTS:
-- Buyer-seller pairs transacting in patterns that suggest coordinated
-- manipulation rather than organic marketplace activity. Coordination
-- manifests as suspiciously regular transaction timing, amounts that
-- match predetermined patterns, bidirectional money flows (buyer and
-- seller swap roles), or pairs that transact exclusively with each other
-- while ignoring the broader marketplace.
--
-- BEHAVIORAL TELL:
-- Organic buyer-seller relationships are asymmetric and irregular. A buyer
-- finds a seller through search, purchases, and may or may not return.
-- Coordinated pairs show symmetry — they find each other immediately,
-- transact at regular intervals, and their transaction amounts follow
-- patterns (round numbers, incrementing values, amounts just below
-- reporting thresholds). When the same entities appear as both buyers
-- and sellers in each other's transaction history, the coordination
-- is structural.
--
-- DATA REQUIREMENTS:
-- Requires: transaction_id, buyer_id, seller_id, transaction_amount,
--           transaction_timestamp
-- Optional: buyer_ip_address, seller_ip_address, buyer_device_id,
--           seller_device_id, payment_method_id
--
-- TUNING PARAMETERS:
-- * min_pair_transactions    — minimum transactions between a pair (default: 4)
-- * regularity_cv_threshold  — coefficient of variation of inter-transaction
--                              days below which timing is suspiciously regular (default: 30%)
-- * round_amount_pct         — % of transactions at round amounts to flag (default: 75%)
-- * lookback_days            — analysis window (default: 180)
--
-- TYPICAL EXPOSURE: $20K–$500K per coordinated pair
-- =============================================================================


-- =============================================================================
-- STEP 1: MAP YOUR COLUMNS HERE
-- =============================================================================

WITH normalized_transactions AS (

    SELECT
        transaction_id          AS transaction_id,           -- expected: VARCHAR / STRING
        buyer_id                AS buyer_id,                 -- expected: VARCHAR / STRING
        seller_id               AS seller_id,                -- expected: VARCHAR / STRING
        amount                  AS transaction_amount,        -- expected: FLOAT / NUMBER
        created_at              AS transaction_timestamp,     -- expected: TIMESTAMP_NTZ
        buyer_ip                AS buyer_ip_address,         -- expected: VARCHAR
        seller_ip               AS seller_ip_address,        -- expected: VARCHAR
        buyer_device             AS buyer_device_id,          -- expected: VARCHAR
        seller_device            AS seller_device_id,         -- expected: VARCHAR

    FROM your_transaction_table                              -- << REPLACE WITH YOUR TABLE

),


-- =============================================================================
-- STEP 2: THRESHOLDS
-- =============================================================================

thresholds AS (
    SELECT
        4       AS min_pair_transactions,       -- 4+ transactions between same pair = investigate
        30.0    AS regularity_cv_threshold,     -- CV < 30% on inter-txn timing = metronomic regularity
        75.0    AS round_amount_pct,            -- 75%+ round-number transactions = predetermined amounts
        180     AS lookback_days
),


-- =============================================================================
-- DETECTION LOGIC — Do not alter below this line
-- =============================================================================

transactions_in_scope AS (
    SELECT *
    FROM normalized_transactions
    WHERE transaction_timestamp >= DATEADD('day', -1 * (SELECT lookback_days FROM thresholds), CURRENT_TIMESTAMP())
),

-- Step 1: Compute pair-level statistics
pair_stats AS (
    SELECT
        buyer_id,
        seller_id,
        COUNT(DISTINCT transaction_id)                      AS pair_transactions,
        SUM(transaction_amount)                             AS pair_gmv,
        AVG(transaction_amount)                             AS avg_txn_amount,
        STDDEV(transaction_amount)                          AS stddev_txn_amount,
        ROUND(100.0 * STDDEV(transaction_amount)
            / NULLIF(AVG(transaction_amount), 0), 1)        AS amount_cv_pct,
        MIN(transaction_timestamp)                          AS first_pair_txn,
        MAX(transaction_timestamp)                          AS last_pair_txn,
        -- Round amount analysis
        ROUND(100.0 * COUNT(CASE
            WHEN MOD(transaction_amount, 10) = 0 THEN 1 END)
            / NULLIF(COUNT(*), 0), 1)                       AS round_amount_pct,
        -- Shared infrastructure
        COUNT(CASE WHEN buyer_ip_address IS NOT NULL
              AND buyer_ip_address = seller_ip_address THEN 1 END)
                                                            AS shared_ip_txns,
        COUNT(CASE WHEN buyer_device_id IS NOT NULL
              AND buyer_device_id = seller_device_id THEN 1 END)
                                                            AS shared_device_txns
    FROM transactions_in_scope
    GROUP BY buyer_id, seller_id
),

-- Step 2: Compute inter-transaction timing regularity
pair_timing AS (
    SELECT
        buyer_id,
        seller_id,
        transaction_timestamp,
        DATEDIFF('hour', LAG(transaction_timestamp) OVER (
            PARTITION BY buyer_id, seller_id
            ORDER BY transaction_timestamp
        ), transaction_timestamp)                           AS hours_since_last
    FROM transactions_in_scope
),

timing_regularity AS (
    SELECT
        buyer_id,
        seller_id,
        AVG(hours_since_last)                               AS avg_hours_between_txns,
        STDDEV(hours_since_last)                            AS stddev_hours_between,
        ROUND(100.0 * STDDEV(hours_since_last)
            / NULLIF(AVG(hours_since_last), 0), 1)          AS timing_cv_pct
    FROM pair_timing
    WHERE hours_since_last IS NOT NULL
    GROUP BY buyer_id, seller_id
),

-- Step 3: Detect bidirectional relationships (buyer↔seller role swapping)
bidirectional_check AS (
    SELECT
        a.buyer_id                                          AS entity_a,
        a.seller_id                                         AS entity_b,
        a.pair_transactions                                 AS a_to_b_txns,
        a.pair_gmv                                          AS a_to_b_gmv,
        b.pair_transactions                                 AS b_to_a_txns,
        b.pair_gmv                                          AS b_to_a_gmv,
        TRUE                                                AS is_bidirectional
    FROM pair_stats a
    INNER JOIN pair_stats b
        ON a.buyer_id = b.seller_id
        AND a.seller_id = b.buyer_id
),

-- Step 4: Measure pair exclusivity (do they transact with anyone else?)
buyer_diversity AS (
    SELECT
        buyer_id,
        COUNT(DISTINCT seller_id)                           AS buyer_total_sellers,
        COUNT(DISTINCT transaction_id)                      AS buyer_total_txns
    FROM transactions_in_scope
    GROUP BY buyer_id
),

pair_exclusivity AS (
    SELECT
        ps.buyer_id,
        ps.seller_id,
        ps.pair_transactions,
        bd.buyer_total_txns,
        ROUND(100.0 * ps.pair_transactions
            / NULLIF(bd.buyer_total_txns, 0), 1)            AS pair_exclusivity_pct
    FROM pair_stats ps
    INNER JOIN buyer_diversity bd
        ON ps.buyer_id = bd.buyer_id
),

-- Step 5: Score and flag
flagged_pairs AS (
    SELECT
        ps.*,
        tr.timing_cv_pct,
        tr.avg_hours_between_txns,
        COALESCE(bc.is_bidirectional, FALSE)                AS is_bidirectional,
        COALESCE(bc.b_to_a_txns, 0)                        AS reverse_txns,
        COALESCE(bc.b_to_a_gmv, 0)                         AS reverse_gmv,
        pe.pair_exclusivity_pct,
        CASE
            WHEN COALESCE(bc.is_bidirectional, FALSE) = TRUE
             AND ps.shared_ip_txns > 0                      THEN 'HIGH — Bidirectional + Shared Infrastructure'
            WHEN COALESCE(bc.is_bidirectional, FALSE) = TRUE
             AND tr.timing_cv_pct <= (SELECT regularity_cv_threshold FROM thresholds)
                                                            THEN 'HIGH — Bidirectional + Regular Timing'
            WHEN tr.timing_cv_pct <= (SELECT regularity_cv_threshold FROM thresholds)
             AND ps.round_amount_pct >= (SELECT round_amount_pct FROM thresholds)
                                                            THEN 'HIGH — Metronomic Timing + Round Amounts'
            WHEN pe.pair_exclusivity_pct >= 80
             AND ps.pair_transactions >= 8                  THEN 'MEDIUM — High Exclusivity Pair'
            WHEN tr.timing_cv_pct <= (SELECT regularity_cv_threshold FROM thresholds)
                                                            THEN 'MEDIUM — Suspiciously Regular Timing'
            WHEN ps.round_amount_pct >= (SELECT round_amount_pct FROM thresholds)
             AND ps.pair_transactions >= 6                  THEN 'MEDIUM — Predetermined Amounts'
            ELSE 'LOW'
        END                                                 AS signal_confidence
    FROM pair_stats ps
    LEFT JOIN timing_regularity tr
        ON ps.buyer_id = tr.buyer_id AND ps.seller_id = tr.seller_id
    LEFT JOIN bidirectional_check bc
        ON ps.buyer_id = bc.entity_a AND ps.seller_id = bc.entity_b
    LEFT JOIN pair_exclusivity pe
        ON ps.buyer_id = pe.buyer_id AND ps.seller_id = pe.seller_id
    CROSS JOIN thresholds t
    WHERE ps.pair_transactions >= t.min_pair_transactions
)


-- =============================================================================
-- FINAL OUTPUT — GLASS BOX VERDICT
-- =============================================================================

SELECT
    buyer_id,
    seller_id,
    pair_transactions,
    pair_gmv,
    avg_txn_amount,
    amount_cv_pct,
    timing_cv_pct,
    avg_hours_between_txns,
    round_amount_pct,
    is_bidirectional,
    reverse_txns,
    pair_exclusivity_pct,
    shared_ip_txns,
    shared_device_txns,

    signal_confidence,
    'Buyer-Seller Coordination'                             AS signal_name,
    'Buyer ' || buyer_id || ' ↔ Seller ' || seller_id
        || ': ' || pair_transactions::VARCHAR || ' transactions, $'
        || ROUND(pair_gmv, 0)::VARCHAR || ' GMV. '
        || CASE WHEN timing_cv_pct IS NOT NULL
           THEN 'Timing regularity CV: ' || timing_cv_pct::VARCHAR || '% (avg '
                || ROUND(avg_hours_between_txns, 0)::VARCHAR || ' hrs between txns). '
           ELSE '' END
        || round_amount_pct::VARCHAR || '% round amounts. '
        || CASE WHEN is_bidirectional
           THEN 'BIDIRECTIONAL: ' || reverse_txns::VARCHAR || ' reverse transactions ($'
                || ROUND(reverse_gmv, 0)::VARCHAR || '). '
           ELSE '' END
        || CASE WHEN shared_ip_txns > 0
           THEN shared_ip_txns::VARCHAR || ' transactions from shared IP. '
           ELSE '' END
        || 'Pair exclusivity: ' || pair_exclusivity_pct::VARCHAR
        || '%.'                                             AS glass_box_verdict

FROM flagged_pairs
ORDER BY signal_confidence, pair_gmv DESC;
