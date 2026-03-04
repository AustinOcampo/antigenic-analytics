-- =============================================================================
-- ANTIGENIC ANALYTICS — SIGNAL: FEE AVOIDANCE SCHEMES
-- =============================================================================
-- File:     fee_avoidance_schemes_detection.sql
-- Signal:   M10 of 10 — Marketplace & Platform Fraud
-- Version:  1.0.0
-- License:  Apache 2.0
--
-- WHAT THIS DETECTS:
-- Systematic structuring of transactions to avoid platform fees or reporting
-- thresholds. Sellers split large orders into smaller components, route
-- partial payments off-platform, or manipulate transaction categorization
-- to qualify for lower fee tiers. The structuring is deliberate — the
-- pattern of amounts just below threshold boundaries cannot occur by chance
-- at the frequencies observed.
--
-- BEHAVIORAL TELL:
-- Organic transaction amounts follow natural distributions — they cluster
-- around product price points with normal variation. Fee avoidance produces
-- unnatural clustering just below specific dollar boundaries (fee tier
-- cutoffs, reporting thresholds, payout limits). A Benford's Law analysis
-- on the leading digits, combined with threshold-proximity analysis, reveals
-- structuring that is invisible in aggregate metrics but unmistakable in
-- the distribution.
--
-- DATA REQUIREMENTS:
-- Requires: transaction_id, seller_id, buyer_id, transaction_amount,
--           transaction_timestamp, platform_fee_amount
-- Optional: listing_id, original_order_amount, split_indicator,
--           fee_tier, payment_method
--
-- TUNING PARAMETERS:
-- * fee_thresholds_array     — known fee tier boundaries (default: [100, 500, 1000, 5000])
-- * proximity_pct            — how close to threshold to flag (default: 5%)
-- * min_transactions         — minimum transactions before analysis (default: 30)
-- * benford_chi_sq_threshold — chi-squared threshold for Benford deviation (default: 15.51)
-- * lookback_days            — analysis window (default: 180)
--
-- TYPICAL EXPOSURE: $15K–$300K in avoided platform fees
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
        platform_fee            AS platform_fee_amount,      -- expected: FLOAT / NUMBER
        listing_id              AS listing_id,               -- expected: VARCHAR (NULL if not tracked)

    FROM your_transaction_table                              -- << REPLACE WITH YOUR TABLE

),


-- =============================================================================
-- STEP 2: THRESHOLDS
-- =============================================================================
-- IMPORTANT: Update fee_thresholds to match YOUR platform's actual fee tier
-- boundaries. The defaults below are illustrative. Your platform may have
-- different breakpoints.
-- =============================================================================

thresholds AS (
    SELECT
        5.0     AS proximity_pct,               -- within 5% below a threshold = suspicious
        30      AS min_transactions,            -- need enough data for distribution analysis
        15.51   AS benford_chi_sq_threshold,    -- chi-sq critical value at p=0.05 with 8 df
        180     AS lookback_days
),

-- Define your platform's fee tier boundaries here
fee_boundaries AS (
    SELECT column1 AS boundary_amount
    FROM VALUES (100), (500), (1000), (5000), (10000)       -- << EDIT TO MATCH YOUR FEE TIERS
),


-- =============================================================================
-- DETECTION LOGIC — Do not alter below this line
-- =============================================================================

transactions_in_scope AS (
    SELECT *
    FROM normalized_transactions
    WHERE transaction_timestamp >= DATEADD('day', -1 * (SELECT lookback_days FROM thresholds), CURRENT_TIMESTAMP())
),

-- Step 1: Threshold proximity analysis per seller
threshold_proximity AS (
    SELECT
        t.seller_id,
        t.transaction_id,
        t.transaction_amount,
        fb.boundary_amount,
        ROUND(100.0 * (fb.boundary_amount - t.transaction_amount)
            / fb.boundary_amount, 2)                        AS pct_below_boundary
    FROM transactions_in_scope t
    CROSS JOIN fee_boundaries fb
    WHERE t.transaction_amount > 0
      AND t.transaction_amount < fb.boundary_amount
      AND t.transaction_amount >= fb.boundary_amount * (1 - (SELECT proximity_pct FROM thresholds) / 100)
),

seller_proximity_stats AS (
    SELECT
        seller_id,
        COUNT(DISTINCT transaction_id)                      AS near_threshold_txns,
        COUNT(DISTINCT boundary_amount)                     AS boundaries_targeted,
        MODE(boundary_amount)                               AS most_targeted_boundary,
        AVG(pct_below_boundary)                             AS avg_pct_below_boundary
    FROM threshold_proximity
    GROUP BY seller_id
),

-- Step 2: Overall seller transaction stats
seller_stats AS (
    SELECT
        seller_id,
        COUNT(DISTINCT transaction_id)                      AS total_transactions,
        SUM(transaction_amount)                             AS total_gmv,
        SUM(platform_fee_amount)                            AS total_fees_paid,
        ROUND(100.0 * SUM(platform_fee_amount)
            / NULLIF(SUM(transaction_amount), 0), 2)        AS effective_fee_rate_pct,
        AVG(transaction_amount)                             AS avg_txn_amount,
        STDDEV(transaction_amount)                          AS stddev_txn_amount,
        -- Amount distribution shape
        PERCENTILE_CONT(0.25) WITHIN GROUP (ORDER BY transaction_amount)
                                                            AS p25_amount,
        PERCENTILE_CONT(0.50) WITHIN GROUP (ORDER BY transaction_amount)
                                                            AS p50_amount,
        PERCENTILE_CONT(0.75) WITHIN GROUP (ORDER BY transaction_amount)
                                                            AS p75_amount
    FROM transactions_in_scope
    GROUP BY seller_id
),

-- Step 3: Benford's Law analysis on first digits
benford_expected AS (
    SELECT column1 AS digit, column2 AS expected_pct
    FROM VALUES
        (1, 30.1), (2, 17.6), (3, 12.5), (4, 9.7),
        (5, 7.9),  (6, 6.7),  (7, 5.8),  (8, 5.1), (9, 4.6)
),

seller_first_digits AS (
    SELECT
        seller_id,
        CAST(LEFT(CAST(FLOOR(ABS(transaction_amount)) AS VARCHAR), 1) AS INTEGER)
                                                            AS first_digit,
        COUNT(*)                                            AS digit_count
    FROM transactions_in_scope
    WHERE transaction_amount >= 1
    GROUP BY seller_id, first_digit
),

seller_benford AS (
    SELECT
        sfd.seller_id,
        SUM(
            POWER(sfd.digit_count - (ss.total_transactions * be.expected_pct / 100), 2)
            / NULLIF(ss.total_transactions * be.expected_pct / 100, 0)
        )                                                   AS benford_chi_sq
    FROM seller_first_digits sfd
    INNER JOIN benford_expected be ON sfd.first_digit = be.digit
    INNER JOIN seller_stats ss ON sfd.seller_id = ss.seller_id
    GROUP BY sfd.seller_id
),

-- Step 4: Detect order splitting (multiple small transactions close in time)
potential_splits AS (
    SELECT
        seller_id,
        buyer_id,
        transaction_timestamp,
        transaction_amount,
        COUNT(*) OVER (
            PARTITION BY seller_id, buyer_id
            ORDER BY transaction_timestamp
            RANGE BETWEEN INTERVAL '15 MINUTES' PRECEDING AND INTERVAL '15 MINUTES' FOLLOWING
        )                                                   AS txns_in_window,
        SUM(transaction_amount) OVER (
            PARTITION BY seller_id, buyer_id
            ORDER BY transaction_timestamp
            RANGE BETWEEN INTERVAL '15 MINUTES' PRECEDING AND INTERVAL '15 MINUTES' FOLLOWING
        )                                                   AS combined_amount_in_window
    FROM transactions_in_scope
),

split_summary AS (
    SELECT
        seller_id,
        COUNT(CASE WHEN txns_in_window >= 2 THEN 1 END)    AS potential_split_txns,
        MAX(txns_in_window)                                 AS max_split_cluster,
        MAX(combined_amount_in_window)                      AS max_combined_amount
    FROM potential_splits
    GROUP BY seller_id
),

-- Step 5: Score and flag
flagged_sellers AS (
    SELECT
        ss.*,
        COALESCE(sps.near_threshold_txns, 0)                AS near_threshold_txns,
        ROUND(100.0 * COALESCE(sps.near_threshold_txns, 0)
            / NULLIF(ss.total_transactions, 0), 1)          AS near_threshold_pct,
        COALESCE(sps.boundaries_targeted, 0)                AS boundaries_targeted,
        COALESCE(sps.most_targeted_boundary, 0)             AS most_targeted_boundary,
        COALESCE(sb.benford_chi_sq, 0)                      AS benford_chi_sq,
        COALESCE(ssp.potential_split_txns, 0)               AS potential_split_txns,
        CASE
            WHEN COALESCE(sps.near_threshold_txns, 0) >= 10
             AND sb.benford_chi_sq >= (SELECT benford_chi_sq_threshold FROM thresholds)
             AND COALESCE(ssp.potential_split_txns, 0) >= 5  THEN 'HIGH — Structuring + Benford Deviation + Splitting'
            WHEN 100.0 * COALESCE(sps.near_threshold_txns, 0) / NULLIF(ss.total_transactions, 0) >= 20
             AND sps.boundaries_targeted >= 2                THEN 'HIGH — Multi-Boundary Structuring'
            WHEN sb.benford_chi_sq >= (SELECT benford_chi_sq_threshold FROM thresholds) * 2
             AND COALESCE(sps.near_threshold_txns, 0) >= 5   THEN 'MEDIUM — Significant Distribution Anomaly'
            WHEN COALESCE(ssp.potential_split_txns, 0) >= 10
             AND 100.0 * COALESCE(sps.near_threshold_txns, 0) / NULLIF(ss.total_transactions, 0) >= 10
                                                            THEN 'MEDIUM — Order Splitting Pattern'
            ELSE 'LOW'
        END                                                 AS signal_confidence
    FROM seller_stats ss
    LEFT JOIN seller_proximity_stats sps ON ss.seller_id = sps.seller_id
    LEFT JOIN seller_benford sb ON ss.seller_id = sb.seller_id
    LEFT JOIN split_summary ssp ON ss.seller_id = ssp.seller_id
    CROSS JOIN thresholds t
    WHERE ss.total_transactions >= t.min_transactions
      AND (
          COALESCE(sps.near_threshold_txns, 0) >= 5
          OR sb.benford_chi_sq >= t.benford_chi_sq_threshold
          OR COALESCE(ssp.potential_split_txns, 0) >= 10
      )
)


-- =============================================================================
-- FINAL OUTPUT — GLASS BOX VERDICT
-- =============================================================================

SELECT
    seller_id,
    total_transactions,
    total_gmv,
    total_fees_paid,
    effective_fee_rate_pct,
    near_threshold_txns,
    near_threshold_pct,
    boundaries_targeted,
    most_targeted_boundary,
    benford_chi_sq,
    potential_split_txns,

    signal_confidence,
    'Fee Avoidance Schemes'                                 AS signal_name,
    'Seller ' || seller_id
        || ': ' || near_threshold_txns::VARCHAR
        || ' transactions (' || near_threshold_pct::VARCHAR
        || '%) clustered just below fee thresholds across '
        || boundaries_targeted::VARCHAR || ' boundaries. '
        || 'Effective fee rate: ' || effective_fee_rate_pct::VARCHAR
        || '%. Benford chi-sq: ' || ROUND(benford_chi_sq, 1)::VARCHAR
        || CASE WHEN benford_chi_sq >= (SELECT benford_chi_sq_threshold FROM thresholds)
           THEN ' (ANOMALOUS). ' ELSE ' (within norms). ' END
        || CASE WHEN potential_split_txns > 0
           THEN potential_split_txns::VARCHAR || ' potential split transactions detected. '
           ELSE '' END
        || 'Total GMV: $' || ROUND(total_gmv, 0)::VARCHAR
        || ', Fees paid: $' || ROUND(total_fees_paid, 0)::VARCHAR
        || '.'                                              AS glass_box_verdict

FROM flagged_sellers
ORDER BY signal_confidence, total_gmv DESC;
