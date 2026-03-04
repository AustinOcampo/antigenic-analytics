-- =============================================================================
-- ANTIGENIC ANALYTICS — SIGNAL: GMV INFLATION
-- =============================================================================
-- File:     gmv_inflation_detection.sql
-- Signal:   M08 of 10 — Marketplace & Platform Fraud
-- Version:  1.0.0
-- License:  Apache 2.0
--
-- WHAT THIS DETECTS:
-- Sellers inflating gross merchandise volume with fake or circular transactions.
-- GMV inflation serves multiple purposes: hitting volume-based tier thresholds
-- for lower commission rates, qualifying for featured placement or badges,
-- manufacturing social proof ("10,000+ sold"), or laundering money through
-- the platform. The transactions appear completed but the economic substance
-- is hollow — goods are never shipped, or the same goods cycle between
-- affiliated accounts.
--
-- BEHAVIORAL TELL:
-- Real transactions produce real logistics: shipping events, delivery
-- confirmations, and organic review patterns. Inflated GMV shows transactions
-- that complete instantly or with minimal shipping activity, buyer accounts
-- that purchase but never review or return, circular money flows where payment
-- amounts return to the seller through connected accounts, and transaction
-- amounts that cluster at strategic tier boundaries.
--
-- DATA REQUIREMENTS:
-- Requires: transaction_id, seller_id, buyer_id, transaction_amount,
--           transaction_timestamp, transaction_status, shipping_status
-- Optional: shipping_tracking_id, delivery_timestamp, review_id,
--           buyer_device_id, buyer_ip_address, seller_ip_address
--
-- TUNING PARAMETERS:
-- * min_transactions         — minimum transactions before analysis (default: 20)
-- * no_ship_rate_threshold   — % completed with no shipping to flag (default: 30%)
-- * no_review_rate_threshold — % completed with no review to flag (default: 90%)
-- * circular_buyer_threshold — % of GMV from repeat buyer cluster (default: 50%)
-- * lookback_days            — analysis window (default: 180)
--
-- TYPICAL EXPOSURE: $50K–$2M in inflated platform metrics
-- =============================================================================


-- =============================================================================
-- STEP 1: MAP YOUR COLUMNS HERE
-- =============================================================================

WITH normalized_transactions AS (

    SELECT
        transaction_id          AS transaction_id,           -- expected: VARCHAR / STRING
        seller_id               AS seller_id,                -- expected: VARCHAR / STRING
        buyer_id                AS buyer_id,                 -- expected: VARCHAR / STRING
        amount                  AS transaction_amount,        -- expected: FLOAT / NUMBER
        created_at              AS transaction_timestamp,     -- expected: TIMESTAMP_NTZ
        status                  AS transaction_status,       -- expected: VARCHAR ('completed','shipped','cancelled')
        shipping_status         AS shipping_status,          -- expected: VARCHAR ('shipped','delivered','none',NULL)
        tracking_id             AS shipping_tracking_id,     -- expected: VARCHAR (NULL if no shipping)
        delivered_at            AS delivery_timestamp,        -- expected: TIMESTAMP_NTZ (NULL if not delivered)
        buyer_ip_address        AS buyer_ip_address,         -- expected: VARCHAR
        buyer_device_id         AS buyer_device_id,          -- expected: VARCHAR

    FROM your_transaction_table                              -- << REPLACE WITH YOUR TABLE

),

normalized_reviews AS (

    SELECT
        review_id               AS review_id,                -- expected: VARCHAR / STRING
        transaction_id          AS transaction_id,           -- expected: VARCHAR / STRING

    FROM your_review_table                                   -- << REPLACE WITH YOUR TABLE

),


-- =============================================================================
-- STEP 2: THRESHOLDS
-- =============================================================================

thresholds AS (
    SELECT
        20      AS min_transactions,            -- need volume to establish pattern vs noise
        30.0    AS no_ship_rate_threshold,      -- 30%+ "completed" with no shipping = suspicious
        90.0    AS no_review_rate_threshold,    -- 90%+ no reviews on completed transactions = hollow
        50.0    AS circular_buyer_threshold,    -- 50%+ GMV from concentrated buyer cluster = circular
        180     AS lookback_days
),


-- =============================================================================
-- DETECTION LOGIC — Do not alter below this line
-- =============================================================================

transactions_in_scope AS (
    SELECT *
    FROM normalized_transactions
    WHERE transaction_timestamp >= DATEADD('day', -1 * (SELECT lookback_days FROM thresholds), CURRENT_TIMESTAMP())
      AND transaction_status = 'completed'
),

-- Step 1: Seller-level transaction quality metrics
seller_quality AS (
    SELECT
        t.seller_id,
        COUNT(DISTINCT t.transaction_id)                    AS total_completed,
        SUM(t.transaction_amount)                           AS total_gmv,
        -- Shipping analysis
        COUNT(CASE WHEN t.shipping_tracking_id IS NULL
              AND t.shipping_status IN ('none', NULL)
              THEN 1 END)                                   AS no_ship_count,
        ROUND(100.0 * COUNT(CASE WHEN t.shipping_tracking_id IS NULL
              AND t.shipping_status IN ('none', NULL)
              THEN 1 END)
            / NULLIF(COUNT(*), 0), 1)                       AS no_ship_rate_pct,
        -- Review analysis
        COUNT(CASE WHEN r.review_id IS NULL THEN 1 END)    AS no_review_count,
        ROUND(100.0 * COUNT(CASE WHEN r.review_id IS NULL THEN 1 END)
            / NULLIF(COUNT(*), 0), 1)                       AS no_review_rate_pct,
        -- Buyer concentration
        COUNT(DISTINCT t.buyer_id)                          AS distinct_buyers,
        ROUND(1.0 * COUNT(*) / NULLIF(COUNT(DISTINCT t.buyer_id), 0), 1)
                                                            AS txns_per_buyer_avg,
        -- Timing
        AVG(CASE WHEN t.delivery_timestamp IS NOT NULL
            THEN DATEDIFF('hour', t.transaction_timestamp, t.delivery_timestamp) END)
                                                            AS avg_hours_to_delivery,
        MIN(t.transaction_timestamp)                        AS first_transaction,
        MAX(t.transaction_timestamp)                        AS last_transaction
    FROM transactions_in_scope t
    LEFT JOIN normalized_reviews r
        ON t.transaction_id = r.transaction_id
    GROUP BY t.seller_id
),

-- Step 2: Buyer concentration — top buyers as % of seller GMV
top_buyer_concentration AS (
    SELECT
        seller_id,
        buyer_id,
        SUM(transaction_amount)                             AS buyer_gmv,
        COUNT(DISTINCT transaction_id)                      AS buyer_txn_count
    FROM transactions_in_scope
    GROUP BY seller_id, buyer_id
),

top_buyer_share AS (
    SELECT
        tbc.seller_id,
        SUM(CASE WHEN tbc.buyer_rank <= 3 THEN tbc.buyer_gmv ELSE 0 END)
                                                            AS top_3_buyer_gmv,
        MAX(sq.total_gmv)                                   AS seller_total_gmv,
        ROUND(100.0 * SUM(CASE WHEN tbc.buyer_rank <= 3 THEN tbc.buyer_gmv ELSE 0 END)
            / NULLIF(MAX(sq.total_gmv), 0), 1)              AS top_3_buyer_gmv_pct
    FROM (
        SELECT
            *,
            ROW_NUMBER() OVER (PARTITION BY seller_id ORDER BY buyer_gmv DESC)
                                                            AS buyer_rank
        FROM top_buyer_concentration
    ) tbc
    INNER JOIN seller_quality sq
        ON tbc.seller_id = sq.seller_id
    GROUP BY tbc.seller_id
),

-- Step 3: Detect shared infrastructure between buyers of same seller
buyer_infra_overlap AS (
    SELECT
        t.seller_id,
        COUNT(DISTINCT CASE
            WHEN t.buyer_ip_address IS NOT NULL THEN t.buyer_ip_address END)
                                                            AS distinct_buyer_ips,
        COUNT(DISTINCT t.buyer_id)                          AS distinct_buyers,
        -- Buyers sharing IPs = possibly same operator
        ROUND(100.0 * COUNT(DISTINCT t.buyer_id)
            / NULLIF(COUNT(DISTINCT CASE
                WHEN t.buyer_ip_address IS NOT NULL THEN t.buyer_ip_address END), 0), 1)
                                                            AS buyers_per_ip_ratio
    FROM transactions_in_scope t
    GROUP BY t.seller_id
),

-- Step 4: Score and flag
flagged_sellers AS (
    SELECT
        sq.*,
        tbs.top_3_buyer_gmv_pct,
        bio.buyers_per_ip_ratio,
        CASE
            WHEN sq.no_ship_rate_pct >= 50
             AND sq.no_review_rate_pct >= 95
             AND tbs.top_3_buyer_gmv_pct >= 70              THEN 'HIGH — Hollow Transactions (No Ship + No Reviews + Concentrated Buyers)'
            WHEN sq.no_ship_rate_pct >= (SELECT no_ship_rate_threshold FROM thresholds)
             AND tbs.top_3_buyer_gmv_pct >= (SELECT circular_buyer_threshold FROM thresholds)
                                                            THEN 'HIGH — Circular Flow Pattern'
            WHEN sq.no_ship_rate_pct >= (SELECT no_ship_rate_threshold FROM thresholds)
             AND sq.no_review_rate_pct >= (SELECT no_review_rate_threshold FROM thresholds)
                                                            THEN 'MEDIUM — No Shipping + No Reviews'
            WHEN tbs.top_3_buyer_gmv_pct >= (SELECT circular_buyer_threshold FROM thresholds)
             AND bio.buyers_per_ip_ratio >= 3                THEN 'MEDIUM — Concentrated Buyers + Shared Infrastructure'
            ELSE 'LOW'
        END                                                 AS signal_confidence
    FROM seller_quality sq
    LEFT JOIN top_buyer_share tbs ON sq.seller_id = tbs.seller_id
    LEFT JOIN buyer_infra_overlap bio ON sq.seller_id = bio.seller_id
    CROSS JOIN thresholds t
    WHERE sq.total_completed >= t.min_transactions
      AND (
          sq.no_ship_rate_pct >= t.no_ship_rate_threshold
          OR tbs.top_3_buyer_gmv_pct >= t.circular_buyer_threshold
      )
)


-- =============================================================================
-- FINAL OUTPUT — GLASS BOX VERDICT
-- =============================================================================

SELECT
    seller_id,
    total_completed,
    total_gmv,
    no_ship_rate_pct,
    no_review_rate_pct,
    distinct_buyers,
    txns_per_buyer_avg,
    top_3_buyer_gmv_pct,
    buyers_per_ip_ratio,

    signal_confidence,
    'GMV Inflation'                                         AS signal_name,
    'Seller ' || seller_id
        || ' has $' || ROUND(total_gmv, 0)::VARCHAR
        || ' GMV across ' || total_completed::VARCHAR
        || ' completed transactions. '
        || no_ship_rate_pct::VARCHAR || '% have no shipping activity. '
        || no_review_rate_pct::VARCHAR || '% have no reviews. '
        || 'Top 3 buyers account for ' || top_3_buyer_gmv_pct::VARCHAR
        || '% of GMV. '
        || distinct_buyers::VARCHAR || ' distinct buyers ('
        || txns_per_buyer_avg::VARCHAR
        || ' txns per buyer avg).'                          AS glass_box_verdict

FROM flagged_sellers
ORDER BY signal_confidence, total_gmv DESC;
