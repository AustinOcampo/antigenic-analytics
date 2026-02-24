-- =============================================================================
-- ANTIGENIC ANALYTICS — SIGNAL: REFUND ABUSE (REFUND-AS-A-SERVICE)
-- =============================================================================
-- File:     refund_abuse_detection.sql
-- Signal:   P01 of 10 — Payments & Gateways
-- Version:  1.0.0
-- License:  Apache 2.0
--
-- WHAT THIS DETECTS:
-- Customers who have engineered refunds into a repeatable revenue stream.
-- This goes beyond the occasional legitimate return. These are accounts with
-- behavioral patterns — high refund rates, refunds concentrated on high-value
-- items, refunds shortly after delivery confirmation, or accounts that cycle
-- through refund-then-repurchase loops — that indicate deliberate exploitation
-- of your return policy.
--
-- BEHAVIORAL TELL:
-- Legitimate customers refund occasionally and irregularly. Refund abusers
-- show consistency — same item categories, same timing relative to delivery,
-- same dollar bands. The pattern is the tell. A customer with a 70% refund
-- rate across 20 orders is not having bad luck. They have a system.
--
-- DATA REQUIREMENTS:
-- Requires: transaction_id, customer_id, order_amount, transaction_status,
--           transaction_timestamp, refund_amount, refund_timestamp
-- Optional: product_category, shipping_address, ip_address
--
-- TUNING PARAMETERS:
-- * min_order_count          — minimum orders before flagging (default: 3)
-- * refund_rate_threshold    — refund rate % above which to flag (default: 40%)
-- * min_refund_amount        — minimum total refunded to surface (default: $200)
-- * refund_velocity_days     — days post-purchase within which refund is suspicious (default: 3)
--
-- TYPICAL EXPOSURE: $10,000 — $500,000
-- =============================================================================


-- =============================================================================
-- STEP 1: MAP YOUR COLUMNS AND SET YOUR THRESHOLDS
-- =============================================================================

WITH normalized_transactions AS (

    SELECT
        transaction_id          AS transaction_id,          -- expected: VARCHAR
        customer_id             AS customer_id,             -- expected: VARCHAR
        order_amount            AS order_amount,            -- expected: FLOAT
        refund_amount           AS refund_amount,           -- expected: FLOAT (0 if no refund)
        transaction_status      AS transaction_status,      -- expected: VARCHAR ('paid','refunded','partial')
        created_at              AS transaction_timestamp,   -- expected: TIMESTAMP_NTZ
        refunded_at             AS refund_timestamp,        -- expected: TIMESTAMP_NTZ (NULL if no refund)
        product_category        AS product_category,        -- expected: VARCHAR (NULL ok)
        shipping_address        AS shipping_address,        -- expected: VARCHAR (NULL ok)
        ip_address              AS ip_address               -- expected: VARCHAR (NULL ok)

    FROM your_orders_table          -- << CHANGE THIS (Stripe: charges/refunds, Shopify: orders)

    WHERE
        created_at >= DATEADD('year', -2, CURRENT_DATE)

),

thresholds AS (
    SELECT
        3       AS min_order_count,             -- Minimum orders before pattern is meaningful
        40.0    AS refund_rate_threshold,       -- Flag if refund rate exceeds 40%
        200     AS min_refund_amount,           -- Minimum total refunded to surface
        3       AS refund_velocity_days         -- Refund within N days of purchase = suspicious
),


-- =============================================================================
-- STEP 2: ANTIGENIC ANALYTICS DETECTION LOGIC
-- =============================================================================

-- Customer-level order and refund statistics
customer_stats AS (
    SELECT
        customer_id,
        COUNT(DISTINCT transaction_id)                      AS total_orders,
        SUM(order_amount)                                   AS total_order_value,
        SUM(COALESCE(refund_amount, 0))                     AS total_refunded,
        COUNT(CASE WHEN transaction_status IN ('refunded','partially_refunded')
                   THEN 1 END)                              AS refund_count,
        -- Rapid refund count: refunded within N days of purchase
        COUNT(CASE WHEN refund_timestamp IS NOT NULL
                    AND DATEDIFF('day', transaction_timestamp, refund_timestamp)
                        <= t.refund_velocity_days           THEN 1 END)
                                                            AS rapid_refund_count,
        MIN(transaction_timestamp)                          AS first_order_date,
        MAX(transaction_timestamp)                          AS last_order_date,
        COUNT(DISTINCT product_category)                    AS distinct_categories_ordered,
        -- Most refunded category
        MODE(CASE WHEN transaction_status IN ('refunded','partially_refunded')
                  THEN product_category END)                AS most_refunded_category
    FROM normalized_transactions
    CROSS JOIN thresholds t
    GROUP BY 1
),

-- Compute refund rate and pattern scores
customer_scored AS (
    SELECT
        *,
        ROUND(100.0 * refund_count / NULLIF(total_orders, 0), 1)
                                                            AS refund_rate_pct,
        ROUND(100.0 * total_refunded / NULLIF(total_order_value, 0), 1)
                                                            AS refund_value_rate_pct,
        ROUND(100.0 * rapid_refund_count / NULLIF(refund_count, 0), 1)
                                                            AS rapid_refund_rate_pct,
        ROUND(total_refunded / NULLIF(refund_count, 0), 2)
                                                            AS avg_refund_amount
    FROM customer_stats
),

flagged_customers AS (
    SELECT
        s.*,
        t.refund_rate_threshold,
        t.min_order_count,
        CASE
            WHEN s.refund_rate_pct >= 60
             AND s.rapid_refund_rate_pct >= 50              THEN 'HIGH — Systematic Abuse'
            WHEN s.refund_rate_pct >= t.refund_rate_threshold
             AND s.total_orders >= 5                        THEN 'HIGH — Repeat Pattern'
            WHEN s.refund_rate_pct >= t.refund_rate_threshold THEN 'MEDIUM — Elevated Rate'
            WHEN s.rapid_refund_rate_pct >= 75              THEN 'MEDIUM — Rapid Refund Pattern'
            ELSE 'LOW'
        END                                                 AS signal_confidence
    FROM customer_scored s
    CROSS JOIN thresholds t
    WHERE
        s.total_orders >= t.min_order_count
        AND s.total_refunded >= t.min_refund_amount
        AND (
            s.refund_rate_pct >= t.refund_rate_threshold
            OR s.rapid_refund_rate_pct >= 75
        )
)


-- =============================================================================
-- FINAL OUTPUT — GLASS BOX VERDICT
-- =============================================================================

SELECT
    customer_id,
    total_orders,
    total_order_value,
    total_refunded,
    refund_count,
    refund_rate_pct,
    refund_value_rate_pct,
    rapid_refund_count,
    rapid_refund_rate_pct,
    avg_refund_amount,
    most_refunded_category,
    first_order_date,
    last_order_date,

    signal_confidence,
    'Refund Abuse'                                          AS signal_name,
    'Customer ' || customer_id
        || ' has refunded ' || refund_count::VARCHAR
        || ' of ' || total_orders::VARCHAR || ' orders ('
        || refund_rate_pct::VARCHAR || '% refund rate), totaling $'
        || ROUND(total_refunded, 0)::VARCHAR
        || ' refunded. ' || rapid_refund_count::VARCHAR
        || ' refunds occurred within ' || refund_velocity_days::VARCHAR
        || ' days of purchase (' || rapid_refund_rate_pct::VARCHAR
        || '% rapid refund rate).'                         AS glass_box_verdict

FROM flagged_customers
ORDER BY signal_confidence, total_refunded DESC;
