-- =============================================================================
-- ANTIGENIC ANALYTICS — SIGNAL: FIRST-TIME DISCOUNT FARMING
-- =============================================================================
-- File:     first_time_discount_farming_detection.sql
-- Signal:   L12 of 13 — Loyalty, Rewards & Promotion Fraud
-- Version:  1.0.0
-- License:  Apache 2.0
--
-- WHAT THIS DETECTS:
-- Clusters of "new" accounts created specifically to redeem first-purchase
-- discounts, welcome bonuses, or new-member promotions repeatedly. The
-- accounts share devices, IPs, payment methods, or shipping addresses —
-- revealing that the same operator is harvesting introductory offers at
-- scale by manufacturing new identities for every redemption.
--
-- BEHAVIORAL TELL:
-- Legitimate new customers arrive from diverse sources, explore the product,
-- and show varied first-purchase behavior. Discount farmers create accounts
-- in batches, redeem the first-purchase offer immediately, and show zero
-- engagement beyond the discounted transaction. The accounts are single-use:
-- one signup, one discounted purchase, no second order. When you connect
-- them by device or payment fingerprint, the cluster structure emerges.
--
-- DATA REQUIREMENTS:
-- Requires: member_id, account_created_at, first_order_date, first_order_amount,
--           first_order_discount, device_id, ip_address
-- Optional: payment_method_fingerprint, email_domain, shipping_address_hash,
--           second_order_date, promo_code_used, total_orders
--
-- TUNING PARAMETERS:
-- * min_cluster_size         — minimum accounts sharing infra to flag (default: 3)
-- * max_account_age_days     — accounts older than this aren't "first-time" farms (default: 30)
-- * single_order_pct_threshold — % of cluster with only 1 order to flag (default: 80%)
-- * lookback_days            — analysis window (default: 180)
--
-- TYPICAL EXPOSURE: $5,000 — $100,000
-- =============================================================================


-- =============================================================================
-- STEP 1: MAP YOUR COLUMNS AND SET YOUR THRESHOLDS
-- =============================================================================

WITH normalized_members AS (

    SELECT
        member_id               AS member_id,               -- expected: VARCHAR
        created_at              AS account_created_at,       -- expected: TIMESTAMP_NTZ
        first_order_date        AS first_order_date,         -- expected: DATE / TIMESTAMP
        first_order_amount      AS first_order_amount,       -- expected: FLOAT
        first_order_discount    AS first_order_discount,     -- expected: FLOAT (0 if no discount)
        first_promo_code        AS promo_code_used,          -- expected: VARCHAR (NULL if none)
        total_orders            AS total_orders,             -- expected: INTEGER
        device_id               AS device_id,                -- expected: VARCHAR
        ip_address              AS ip_address,               -- expected: VARCHAR
        payment_fingerprint     AS payment_method_fingerprint, -- expected: VARCHAR
        email_domain            AS email_domain,             -- expected: VARCHAR (domain portion)
        shipping_address_hash   AS shipping_address_hash,    -- expected: VARCHAR (hashed)

    FROM your_member_table                                   -- << REPLACE WITH YOUR TABLE

    WHERE created_at >= DATEADD('day', -180, CURRENT_TIMESTAMP())  -- << ADJUST LOOKBACK

),


-- =============================================================================
-- STEP 2: THRESHOLDS
-- =============================================================================

thresholds AS (
    SELECT
        3       AS min_cluster_size,            -- 3+ "new" accounts on same device = farming
        30      AS max_account_age_days,        -- focus on accounts created within 30 days of first order
        80.0    AS single_order_pct_threshold,  -- 80%+ of cluster with only 1 order = disposable accounts
        180     AS lookback_days
),


-- =============================================================================
-- DETECTION LOGIC — Do not alter below this line
-- =============================================================================

-- Filter to accounts that used a first-purchase discount
discount_users AS (
    SELECT *
    FROM normalized_members
    WHERE first_order_discount > 0
      AND DATEDIFF('day', account_created_at, COALESCE(first_order_date, account_created_at))
          <= (SELECT max_account_age_days FROM thresholds)
),

-- Step 1: Link accounts by shared infrastructure
account_links AS (
    SELECT
        a.member_id             AS account_a,
        b.member_id             AS account_b,
        CASE WHEN a.device_id IS NOT NULL AND a.device_id = b.device_id THEN 1 ELSE 0 END
      + CASE WHEN a.ip_address IS NOT NULL AND a.ip_address = b.ip_address THEN 1 ELSE 0 END
      + CASE WHEN a.payment_method_fingerprint IS NOT NULL
             AND a.payment_method_fingerprint = b.payment_method_fingerprint THEN 1 ELSE 0 END
      + CASE WHEN a.shipping_address_hash IS NOT NULL
             AND a.shipping_address_hash = b.shipping_address_hash THEN 1 ELSE 0 END
                                                            AS shared_signals
    FROM discount_users a
    INNER JOIN discount_users b
        ON a.member_id < b.member_id
    WHERE a.device_id = b.device_id
       OR a.ip_address = b.ip_address
       OR a.payment_method_fingerprint = b.payment_method_fingerprint
       OR a.shipping_address_hash = b.shipping_address_hash
),

-- Step 2: Build clusters
cluster_seeds AS (
    SELECT account_a AS member_id, account_a AS cluster_root FROM account_links WHERE shared_signals >= 1
    UNION
    SELECT account_b AS member_id, account_a AS cluster_root FROM account_links WHERE shared_signals >= 1
),

cluster_assignment AS (
    SELECT member_id, MIN(cluster_root) AS cluster_id
    FROM cluster_seeds
    GROUP BY member_id
),

-- Step 3: Cluster metrics
cluster_metrics AS (
    SELECT
        ca.cluster_id,
        COUNT(DISTINCT ca.member_id)                        AS cluster_size,
        ARRAY_AGG(DISTINCT ca.member_id)                    AS cluster_accounts,
        -- Discount extraction
        SUM(du.first_order_discount)                        AS total_discount_captured,
        AVG(du.first_order_discount)                        AS avg_discount_per_account,
        SUM(du.first_order_amount)                          AS total_first_order_spend,
        -- Single-order analysis (disposable accounts)
        COUNT(CASE WHEN du.total_orders <= 1 THEN 1 END)   AS single_order_accounts,
        ROUND(100.0 * COUNT(CASE WHEN du.total_orders <= 1 THEN 1 END)
            / NULLIF(COUNT(*), 0), 1)                       AS single_order_pct,
        -- Timing
        MIN(du.account_created_at)                          AS first_account_created,
        MAX(du.account_created_at)                          AS last_account_created,
        DATEDIFF('hour', MIN(du.account_created_at),
                 MAX(du.account_created_at))                AS creation_span_hours,
        -- Infrastructure
        COUNT(DISTINCT du.device_id)                        AS distinct_devices,
        COUNT(DISTINCT du.ip_address)                       AS distinct_ips,
        COUNT(DISTINCT du.payment_method_fingerprint)       AS distinct_payment_methods,
        COUNT(DISTINCT du.email_domain)                     AS distinct_email_domains,
        COUNT(DISTINCT du.shipping_address_hash)            AS distinct_shipping_addresses,
        -- Promo usage
        COUNT(DISTINCT du.promo_code_used)                  AS distinct_promo_codes
    FROM cluster_assignment ca
    INNER JOIN discount_users du
        ON ca.member_id = du.member_id
    GROUP BY ca.cluster_id
),

-- Step 4: Score and flag
flagged_clusters AS (
    SELECT
        cm.*,
        CASE
            WHEN cm.cluster_size >= 8
             AND cm.single_order_pct >= 90
             AND cm.distinct_devices <= 2                    THEN 'HIGH — Large-Scale Discount Farm'
            WHEN cm.cluster_size >= (SELECT min_cluster_size FROM thresholds)
             AND cm.single_order_pct >= (SELECT single_order_pct_threshold FROM thresholds)
             AND cm.creation_span_hours <= 48                THEN 'HIGH — Rapid Batch Creation + No Retention'
            WHEN cm.cluster_size >= (SELECT min_cluster_size FROM thresholds)
             AND cm.single_order_pct >= (SELECT single_order_pct_threshold FROM thresholds)
                                                            THEN 'MEDIUM — Disposable Account Cluster'
            WHEN cm.cluster_size >= 5
             AND cm.distinct_devices <= 2                    THEN 'MEDIUM — Shared Infrastructure Farm'
            ELSE 'LOW'
        END                                                 AS signal_confidence
    FROM cluster_metrics cm
    CROSS JOIN thresholds t
    WHERE cm.cluster_size >= t.min_cluster_size
)


-- =============================================================================
-- FINAL OUTPUT — GLASS BOX VERDICT
-- =============================================================================

SELECT
    cluster_id,
    cluster_size,
    cluster_accounts,
    total_discount_captured,
    avg_discount_per_account,
    single_order_pct,
    single_order_accounts,
    creation_span_hours,
    distinct_devices,
    distinct_ips,
    distinct_payment_methods,
    distinct_email_domains,
    distinct_promo_codes,

    signal_confidence,
    'First-Time Discount Farming'                           AS signal_name,
    'Cluster of ' || cluster_size::VARCHAR
        || ' "new" accounts sharing infrastructure. $'
        || ROUND(total_discount_captured, 0)::VARCHAR
        || ' total first-purchase discounts captured. '
        || single_order_pct::VARCHAR || '% have only one order (disposable). '
        || 'Created within ' || creation_span_hours::VARCHAR || ' hours. '
        || distinct_devices::VARCHAR || ' devices, '
        || distinct_ips::VARCHAR || ' IPs, '
        || distinct_payment_methods::VARCHAR || ' payment methods, '
        || distinct_email_domains::VARCHAR
        || ' email domains.'                                AS glass_box_verdict

FROM flagged_clusters
ORDER BY signal_confidence, total_discount_captured DESC;
