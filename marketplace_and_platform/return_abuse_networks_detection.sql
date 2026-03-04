-- =============================================================================
-- ANTIGENIC ANALYTICS — SIGNAL: RETURN ABUSE NETWORKS
-- =============================================================================
-- File:     return_abuse_networks_detection.sql
-- Signal:   M05 of 10 — Marketplace & Platform Fraud
-- Version:  1.0.0
-- License:  Apache 2.0
--
-- WHAT THIS DETECTS:
-- Organized return abuse where buyers and sellers collude to extract refunds
-- from the platform. In marketplace environments, return fraud becomes networked:
-- buyer accounts purchase from specific sellers, initiate returns claiming
-- non-delivery or defective goods, and the platform absorbs the loss while
-- both parties retain value. The network structure — repeated buyer-seller
-- pairs with abnormal return rates — is the behavioral signature.
--
-- BEHAVIORAL TELL:
-- Organic returns are distributed randomly across buyer-seller pairs. Return
-- abuse networks show concentration — the same buyer returns to the same
-- sellers repeatedly, return reasons are templated, and the timing between
-- purchase and return is suspiciously consistent. The buyer's return rate
-- with specific sellers far exceeds their return rate with the marketplace
-- at large.
--
-- DATA REQUIREMENTS:
-- Requires: transaction_id, buyer_id, seller_id, transaction_amount,
--           transaction_timestamp, transaction_status, return_reason,
--           return_timestamp
-- Optional: return_amount, shipping_tracking_id, buyer_ip_address,
--           buyer_device_id, product_category
--
-- TUNING PARAMETERS:
-- * min_transactions_per_pair — minimum transactions between a pair (default: 3)
-- * return_rate_threshold     — pair return rate to flag (default: 50%)
-- * min_return_amount         — minimum return value to surface (default: $200)
-- * platform_avg_return_rate  — expected organic return rate (default: 10%)
-- * lookback_days             — analysis window (default: 180)
--
-- TYPICAL EXPOSURE: $15K–$300K per network
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
        status                  AS transaction_status,       -- expected: VARCHAR ('completed','returned','disputed')
        return_reason           AS return_reason,            -- expected: VARCHAR (NULL if no return)
        returned_at             AS return_timestamp,         -- expected: TIMESTAMP_NTZ (NULL if no return)
        return_amount           AS return_amount,            -- expected: FLOAT (NULL if no return)
        category                AS product_category,         -- expected: VARCHAR

    FROM your_transaction_table                              -- << REPLACE WITH YOUR TABLE

),


-- =============================================================================
-- STEP 2: THRESHOLDS
-- =============================================================================

thresholds AS (
    SELECT
        3       AS min_transactions_per_pair,   -- need at least 3 transactions to establish a pattern
        50.0    AS return_rate_threshold,       -- 50%+ return rate between a specific pair = abnormal
        200     AS min_return_amount,           -- filter out trivially small abuse
        10.0    AS platform_avg_return_rate,    -- organic return rate baseline (~8-12% for most marketplaces)
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

-- Step 1: Compute buyer-seller pair statistics
pair_stats AS (
    SELECT
        buyer_id,
        seller_id,
        COUNT(DISTINCT transaction_id)                      AS total_transactions,
        SUM(transaction_amount)                             AS total_spend,
        COUNT(CASE WHEN transaction_status IN ('returned','refunded')
              THEN 1 END)                                   AS return_count,
        SUM(CASE WHEN transaction_status IN ('returned','refunded')
            THEN COALESCE(return_amount, transaction_amount) ELSE 0 END)
                                                            AS total_returned,
        ROUND(100.0 * COUNT(CASE WHEN transaction_status IN ('returned','refunded')
              THEN 1 END)
            / NULLIF(COUNT(*), 0), 1)                       AS pair_return_rate_pct,
        AVG(CASE WHEN return_timestamp IS NOT NULL
            THEN DATEDIFF('day', transaction_timestamp, return_timestamp) END)
                                                            AS avg_days_to_return,
        STDDEV(CASE WHEN return_timestamp IS NOT NULL
            THEN DATEDIFF('day', transaction_timestamp, return_timestamp) END)
                                                            AS stddev_days_to_return,
        MODE(return_reason)                                 AS most_common_return_reason,
        COUNT(DISTINCT return_reason)                       AS distinct_return_reasons,
        MIN(transaction_timestamp)                          AS first_transaction,
        MAX(transaction_timestamp)                          AS last_transaction
    FROM transactions_in_scope
    GROUP BY buyer_id, seller_id
),

-- Step 2: Compute buyer's overall return rate for comparison
buyer_overall AS (
    SELECT
        buyer_id,
        COUNT(DISTINCT transaction_id)                      AS buyer_total_transactions,
        ROUND(100.0 * COUNT(CASE WHEN transaction_status IN ('returned','refunded')
              THEN 1 END)
            / NULLIF(COUNT(*), 0), 1)                       AS buyer_overall_return_rate,
        COUNT(DISTINCT seller_id)                           AS buyer_distinct_sellers
    FROM transactions_in_scope
    GROUP BY buyer_id
),

-- Step 3: Identify pairs where return rate is anomalous vs buyer baseline
pair_anomalies AS (
    SELECT
        ps.*,
        bo.buyer_overall_return_rate,
        bo.buyer_total_transactions,
        bo.buyer_distinct_sellers,
        ps.pair_return_rate_pct - bo.buyer_overall_return_rate
                                                            AS return_rate_elevation,
        ps.pair_return_rate_pct / NULLIF((SELECT platform_avg_return_rate FROM thresholds), 0)
                                                            AS rate_vs_platform_multiple
    FROM pair_stats ps
    INNER JOIN buyer_overall bo
        ON ps.buyer_id = bo.buyer_id
    CROSS JOIN thresholds t
    WHERE ps.total_transactions >= t.min_transactions_per_pair
      AND ps.total_returned >= t.min_return_amount
      AND ps.pair_return_rate_pct >= t.return_rate_threshold
),

-- Step 4: Detect network structure — buyers connected to multiple flagged sellers
network_buyers AS (
    SELECT
        buyer_id,
        COUNT(DISTINCT seller_id)                           AS flagged_seller_connections,
        SUM(total_returned)                                 AS network_total_returned,
        SUM(total_transactions)                             AS network_total_transactions
    FROM pair_anomalies
    GROUP BY buyer_id
),

-- Step 5: Score and flag
flagged_pairs AS (
    SELECT
        pa.*,
        COALESCE(nb.flagged_seller_connections, 1)          AS flagged_seller_connections,
        CASE
            WHEN nb.flagged_seller_connections >= 3
             AND pa.pair_return_rate_pct >= 75               THEN 'HIGH — Multi-Seller Return Network'
            WHEN pa.pair_return_rate_pct >= 75
             AND pa.stddev_days_to_return <= 2
             AND pa.return_count >= 5                        THEN 'HIGH — Systematic Abuse (Consistent Timing)'
            WHEN pa.pair_return_rate_pct >= (SELECT return_rate_threshold FROM thresholds)
             AND pa.distinct_return_reasons <= 1             THEN 'MEDIUM — Elevated Rate + Templated Reasons'
            WHEN pa.rate_vs_platform_multiple >= 5           THEN 'MEDIUM — 5x+ Platform Return Rate'
            ELSE 'LOW'
        END                                                 AS signal_confidence
    FROM pair_anomalies pa
    LEFT JOIN network_buyers nb
        ON pa.buyer_id = nb.buyer_id
)


-- =============================================================================
-- FINAL OUTPUT — GLASS BOX VERDICT
-- =============================================================================

SELECT
    buyer_id,
    seller_id,
    total_transactions,
    total_spend,
    return_count,
    total_returned,
    pair_return_rate_pct,
    buyer_overall_return_rate,
    return_rate_elevation,
    avg_days_to_return,
    stddev_days_to_return,
    most_common_return_reason,
    flagged_seller_connections,

    signal_confidence,
    'Return Abuse Networks'                                 AS signal_name,
    'Buyer ' || buyer_id || ' ↔ Seller ' || seller_id
        || ': ' || return_count::VARCHAR || ' returns out of '
        || total_transactions::VARCHAR || ' transactions ('
        || pair_return_rate_pct::VARCHAR || '% pair return rate vs '
        || buyer_overall_return_rate::VARCHAR || '% buyer baseline). $'
        || ROUND(total_returned, 0)::VARCHAR || ' total returned. '
        || 'Avg ' || ROUND(avg_days_to_return, 1)::VARCHAR || ' days to return'
        || CASE WHEN stddev_days_to_return <= 2
           THEN ' (suspiciously consistent timing). '
           ELSE '. ' END
        || CASE WHEN flagged_seller_connections >= 2
           THEN 'Buyer connected to ' || flagged_seller_connections::VARCHAR
                || ' flagged sellers (network pattern). '
           ELSE '' END
        || 'Primary reason: "' || COALESCE(most_common_return_reason, 'N/A')
        || '".'                                             AS glass_box_verdict

FROM flagged_pairs
ORDER BY signal_confidence, total_returned DESC;
