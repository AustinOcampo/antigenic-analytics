-- =============================================================================
-- ANTIGENIC ANALYTICS — SIGNAL: RETURN FRAUD
-- =============================================================================
-- File:     return_fraud_detection.sql
-- Signal:   P09 of 10 — Payments & Gateways
-- Version:  1.0.0
-- License:  Apache 2.0
--
-- WHAT THIS DETECTS:
-- Systematic exploitation of return and exchange policies beyond normal
-- customer behavior. This includes: returning used or damaged goods as
-- new, wardrobing (buying items for one-time use then returning),
-- returning empty boxes or counterfeit items, and coordinated return
-- rings that exploit your restocking and refund workflows.
--
-- BEHAVIORAL TELL:
-- Return fraud has a distinct rhythm: purchases cluster before high-use
-- events (purchases before weekends, returns after), high return rates
-- on specific SKU categories (apparel, electronics), returns without
-- original packaging, and customers whose return-to-purchase ratio
-- consistently exceeds normal population norms by a wide margin.
--
-- DATA REQUIREMENTS:
-- Requires: transaction_id, customer_id, order_amount, product_category,
--           transaction_status, return_reason, transaction_timestamp
-- Improves with: return_condition, restocking_fee_applied, sku_id
--
-- TUNING PARAMETERS:
-- * min_return_rate          — return rate to flag (default: 35%)
-- * min_orders_analyzed      — minimum orders for pattern (default: 4)
-- * wardrobing_window_days   — buy-return cycle length (default: 14 days)
-- * min_return_value         — minimum total return value (default: $300)
--
-- TYPICAL EXPOSURE: $10,000 — $150,000
-- =============================================================================

WITH normalized_transactions AS (
    SELECT
        transaction_id          AS transaction_id,
        customer_id             AS customer_id,
        order_amount            AS order_amount,
        product_category        AS product_category,
        transaction_status      AS transaction_status,      -- 'returned', 'refunded', 'completed'
        return_reason           AS return_reason,           -- expected: VARCHAR (NULL ok)
        created_at              AS transaction_timestamp,
        returned_at             AS return_timestamp         -- expected: TIMESTAMP_NTZ (NULL ok)
    FROM your_orders_table          -- << CHANGE THIS
    WHERE created_at >= DATEADD('year', -2, CURRENT_DATE)
),

thresholds AS (
    SELECT
        35.0    AS min_return_rate,
        4       AS min_orders_analyzed,
        14      AS wardrobing_window_days,
        300     AS min_return_value
),

customer_return_stats AS (
    SELECT
        customer_id,
        COUNT(DISTINCT transaction_id)                      AS total_orders,
        SUM(order_amount)                                   AS total_spend,
        COUNT(DISTINCT CASE WHEN transaction_status IN ('returned','refunded')
                            THEN transaction_id END)        AS return_count,
        SUM(CASE WHEN transaction_status IN ('returned','refunded')
                 THEN order_amount ELSE 0 END)              AS total_returned_value,
        -- Wardrobing: returned within N days of purchase
        COUNT(CASE WHEN transaction_status IN ('returned','refunded')
                    AND return_timestamp IS NOT NULL
                    AND DATEDIFF('day', transaction_timestamp, return_timestamp)
                        <= t.wardrobing_window_days         THEN 1 END)
                                                            AS fast_return_count,
        -- Most returned category
        MODE(CASE WHEN transaction_status IN ('returned','refunded')
                  THEN product_category END)                AS most_returned_category,
        -- Most common return reason
        MODE(return_reason)                                 AS most_common_return_reason
    FROM normalized_transactions
    CROSS JOIN thresholds t
    GROUP BY 1
),

scored AS (
    SELECT
        *,
        ROUND(100.0 * return_count / NULLIF(total_orders, 0), 1)
                                                            AS return_rate_pct,
        ROUND(100.0 * fast_return_count / NULLIF(return_count, 0), 1)
                                                            AS fast_return_rate_pct
    FROM customer_return_stats
)

SELECT
    customer_id,
    total_orders,
    total_spend,
    return_count,
    return_rate_pct,
    total_returned_value,
    fast_return_count,
    fast_return_rate_pct,
    most_returned_category,
    most_common_return_reason,

    CASE
        WHEN return_rate_pct >= 60
         AND fast_return_rate_pct >= 50                    THEN 'HIGH — Wardrobing Pattern'
        WHEN return_rate_pct >= t.min_return_rate
         AND total_orders >= 6                             THEN 'HIGH — Repeat Return Abuser'
        WHEN return_rate_pct >= t.min_return_rate          THEN 'MEDIUM — Elevated Return Rate'
        ELSE 'LOW'
    END                                                     AS signal_confidence,

    'Return Fraud'                                          AS signal_name,
    'Customer ' || customer_id
        || ' returned ' || return_count::VARCHAR
        || ' of ' || total_orders::VARCHAR
        || ' orders (' || return_rate_pct::VARCHAR || '% return rate). '
        || 'Total returned value: $' || ROUND(total_returned_value, 0)::VARCHAR
        || '. ' || fast_return_count::VARCHAR
        || ' returns were within ' || wardrobing_window_days::VARCHAR
        || ' days of purchase. Most returned category: '
        || COALESCE(most_returned_category, 'unspecified')  AS glass_box_verdict

FROM scored
CROSS JOIN thresholds t
WHERE
    return_count >= 2
    AND total_returned_value >= t.min_return_value
    AND return_rate_pct >= t.min_return_rate
    AND total_orders >= t.min_orders_analyzed

ORDER BY signal_confidence, total_returned_value DESC;
