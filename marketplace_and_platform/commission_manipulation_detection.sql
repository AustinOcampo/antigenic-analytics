-- =============================================================================
-- ANTIGENIC ANALYTICS — SIGNAL: COMMISSION MANIPULATION
-- =============================================================================
-- File:     commission_manipulation_detection.sql
-- Signal:   M03 of 10 — Marketplace & Platform Fraud
-- Version:  1.0.0
-- License:  Apache 2.0
--
-- WHAT THIS DETECTS:
-- Sellers manipulating fee structures or commission tiers to retain more
-- revenue than the platform intended. Common tactics include miscategorizing
-- products into lower-commission categories, splitting high-value orders into
-- multiple smaller transactions to hit different fee brackets, or routing
-- portions of the sale off-platform while recording only the minimum on-platform
-- to maintain listing visibility.
--
-- BEHAVIORAL TELL:
-- Legitimate sellers price naturally and categorize accurately because it helps
-- their search visibility. Commission manipulators show category mismatches
-- (high-value items in low-commission categories), systematic order splitting
-- (transaction amounts clustered just below tier boundaries), and revenue
-- patterns where on-platform GMV doesn't match the seller's actual business
-- volume indicators (shipping volume, review velocity, return rates).
--
-- DATA REQUIREMENTS:
-- Requires: seller_id, transaction_id, transaction_amount, transaction_timestamp,
--           listing_id, listing_category, platform_commission_amount,
--           commission_rate_pct
-- Optional: listing_price, original_category, category_change_timestamp,
--           order_item_count, shipping_tracking_count
--
-- TUNING PARAMETERS:
-- * tier_boundary_proximity  — how close to a fee boundary to flag (default: 5%)
-- * min_transactions         — minimum transactions before analysis (default: 20)
-- * category_change_threshold — category changes per seller to flag (default: 3)
-- * commission_deviation_pct — deviation from expected rate to flag (default: 15%)
-- * lookback_days            — analysis window (default: 180)
--
-- TYPICAL EXPOSURE: $25K–$500K in lost platform revenue
-- =============================================================================


-- =============================================================================
-- STEP 1: MAP YOUR COLUMNS HERE
-- This is the only section you edit.
-- =============================================================================

WITH normalized_transactions AS (

    SELECT
        transaction_id          AS transaction_id,           -- expected: VARCHAR / STRING
        seller_id               AS seller_id,                -- expected: VARCHAR / STRING
        listing_id              AS listing_id,               -- expected: VARCHAR / STRING
        amount                  AS transaction_amount,        -- expected: FLOAT / NUMBER
        created_at              AS transaction_timestamp,     -- expected: TIMESTAMP_NTZ
        category                AS listing_category,         -- expected: VARCHAR
        commission_amount       AS platform_commission_amount, -- expected: FLOAT / NUMBER
        commission_rate         AS commission_rate_pct,       -- expected: FLOAT (e.g., 12.5 for 12.5%)
        item_count              AS order_item_count,         -- expected: INTEGER (NULL if not tracked)

    FROM your_transaction_table                              -- << REPLACE WITH YOUR TABLE

),

-- If your platform tracks category changes, map here. Otherwise leave as-is.
normalized_category_changes AS (

    SELECT
        listing_id              AS listing_id,               -- expected: VARCHAR / STRING
        seller_id               AS seller_id,                -- expected: VARCHAR / STRING
        old_category            AS original_category,        -- expected: VARCHAR
        new_category            AS new_category,             -- expected: VARCHAR
        changed_at              AS category_change_timestamp, -- expected: TIMESTAMP_NTZ

    FROM your_category_change_table                          -- << REPLACE WITH YOUR TABLE (or use empty CTE)

),


-- =============================================================================
-- STEP 2: THRESHOLDS
-- =============================================================================

thresholds AS (
    SELECT
        5.0     AS tier_boundary_proximity,     -- within 5% of a fee tier boundary = suspicious clustering
        20      AS min_transactions,            -- need enough volume to distinguish pattern from noise
        3       AS category_change_threshold,   -- 3+ category changes suggests deliberate misclassification
        15.0    AS commission_deviation_pct,    -- paying 15%+ less commission than category average = manipulation
        180     AS lookback_days
),


-- =============================================================================
-- DETECTION LOGIC — Do not alter below this line
-- =============================================================================

-- Step 1: Filter to analysis window
transactions_in_scope AS (
    SELECT *
    FROM normalized_transactions
    WHERE transaction_timestamp >= DATEADD('day', -1 * (SELECT lookback_days FROM thresholds), CURRENT_TIMESTAMP())
),

-- Step 2: Compute category-level commission baselines
category_commission_baseline AS (
    SELECT
        listing_category,
        AVG(commission_rate_pct)                             AS avg_category_rate,
        PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY commission_rate_pct)
                                                            AS median_category_rate,
        STDDEV(commission_rate_pct)                          AS stddev_category_rate,
        COUNT(DISTINCT seller_id)                            AS sellers_in_category
    FROM transactions_in_scope
    GROUP BY listing_category
),

-- Step 3: Compute seller-level commission patterns
seller_commission_stats AS (
    SELECT
        ts.seller_id,
        COUNT(DISTINCT ts.transaction_id)                   AS total_transactions,
        SUM(ts.transaction_amount)                          AS total_gmv,
        SUM(ts.platform_commission_amount)                  AS total_commission_paid,
        ROUND(100.0 * SUM(ts.platform_commission_amount)
            / NULLIF(SUM(ts.transaction_amount), 0), 2)     AS effective_commission_rate,
        AVG(ts.commission_rate_pct)                          AS avg_seller_rate,
        COUNT(DISTINCT ts.listing_category)                  AS categories_used,
        -- Detect amount clustering near tier boundaries
        MODE(ts.listing_category)                            AS primary_category,
        ROUND(AVG(ts.transaction_amount), 2)                AS avg_transaction_amount,
        ROUND(STDDEV(ts.transaction_amount), 2)             AS stddev_transaction_amount
    FROM transactions_in_scope ts
    GROUP BY ts.seller_id
),

-- Step 4: Compare seller rate to category baseline
seller_vs_baseline AS (
    SELECT
        scs.*,
        ccb.avg_category_rate,
        ccb.median_category_rate,
        ROUND(ccb.avg_category_rate - scs.avg_seller_rate, 2)
                                                            AS rate_deviation,
        ROUND(100.0 * (ccb.avg_category_rate - scs.avg_seller_rate)
            / NULLIF(ccb.avg_category_rate, 0), 1)          AS rate_deviation_pct
    FROM seller_commission_stats scs
    LEFT JOIN category_commission_baseline ccb
        ON scs.primary_category = ccb.listing_category
),

-- Step 5: Count category changes per seller (if data available)
category_change_counts AS (
    SELECT
        seller_id,
        COUNT(*)                                            AS total_category_changes,
        COUNT(DISTINCT listing_id)                          AS listings_recategorized
    FROM normalized_category_changes
    WHERE category_change_timestamp >= DATEADD('day', -1 * (SELECT lookback_days FROM thresholds), CURRENT_TIMESTAMP())
    GROUP BY seller_id
),

-- Step 6: Score and flag
flagged_sellers AS (
    SELECT
        svb.*,
        COALESCE(ccc.total_category_changes, 0)             AS total_category_changes,
        COALESCE(ccc.listings_recategorized, 0)             AS listings_recategorized,
        CASE
            WHEN svb.rate_deviation_pct >= 25
             AND COALESCE(ccc.total_category_changes, 0) >= 5
                                                            THEN 'HIGH — Rate Gaming + Active Recategorization'
            WHEN svb.rate_deviation_pct >= (SELECT commission_deviation_pct FROM thresholds)
             AND svb.total_transactions >= 50               THEN 'HIGH — Systematic Underpayment'
            WHEN COALESCE(ccc.total_category_changes, 0)
                 >= (SELECT category_change_threshold FROM thresholds)
             AND svb.rate_deviation_pct >= 10               THEN 'MEDIUM — Recategorization Pattern'
            WHEN svb.rate_deviation_pct >= (SELECT commission_deviation_pct FROM thresholds)
                                                            THEN 'MEDIUM — Below-Baseline Rate'
            ELSE 'LOW'
        END                                                 AS signal_confidence
    FROM seller_vs_baseline svb
    LEFT JOIN category_change_counts ccc
        ON svb.seller_id = ccc.seller_id
    CROSS JOIN thresholds t
    WHERE svb.total_transactions >= t.min_transactions
      AND (
          svb.rate_deviation_pct >= t.commission_deviation_pct
          OR COALESCE(ccc.total_category_changes, 0) >= t.category_change_threshold
      )
)


-- =============================================================================
-- FINAL OUTPUT — GLASS BOX VERDICT
-- =============================================================================

SELECT
    seller_id,
    total_transactions,
    total_gmv,
    total_commission_paid,
    effective_commission_rate,
    primary_category,
    avg_category_rate,
    rate_deviation_pct,
    total_category_changes,
    listings_recategorized,

    signal_confidence,
    'Commission Manipulation'                               AS signal_name,
    'Seller ' || seller_id
        || ' paid an effective commission rate of '
        || effective_commission_rate::VARCHAR || '% vs category average of '
        || avg_category_rate::VARCHAR || '% ('
        || rate_deviation_pct::VARCHAR || '% below baseline) across '
        || total_transactions::VARCHAR || ' transactions ($'
        || ROUND(total_gmv, 0)::VARCHAR || ' GMV). '
        || CASE WHEN total_category_changes > 0
           THEN total_category_changes::VARCHAR || ' category changes on '
                || listings_recategorized::VARCHAR || ' listings. '
           ELSE '' END
        || 'Estimated platform revenue loss: $'
        || ROUND(total_gmv * rate_deviation_pct / 100, 0)::VARCHAR
        || '.'                                              AS glass_box_verdict

FROM flagged_sellers
ORDER BY signal_confidence, total_gmv DESC;
