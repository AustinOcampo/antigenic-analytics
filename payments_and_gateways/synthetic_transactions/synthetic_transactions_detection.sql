-- =============================================================================
-- ANTIGENIC ANALYTICS — SIGNAL: SYNTHETIC TRANSACTION PATTERNS
-- =============================================================================
-- File:     synthetic_transactions_detection.sql
-- Signal:   P10 of 10 — Payments & Gateways
-- Version:  1.0.0
-- License:  Apache 2.0
--
-- WHAT THIS DETECTS:
-- Fabricated transaction sequences constructed to mimic legitimate purchasing
-- behavior while concealing money movement, artificially inflating GMV,
-- or generating fraudulent commissions and affiliate payouts. Common in
-- marketplace fraud, affiliate fraud rings, and internal GMV manipulation.
-- These sequences look real individually — the fraud only becomes visible
-- when you analyze the statistical shape of the activity.
--
-- BEHAVIORAL TELL:
-- Real customer behavior is messy and irregular. Synthetic transactions
-- are too clean: amounts cluster in narrow bands, time intervals between
-- transactions are suspiciously regular, conversion rates on specific
-- traffic sources are impossibly high, and the accounts funding the
-- transactions share too many identifiers. The mathematical regularity
-- is the tell — nature doesn't produce that kind of consistency.
--
-- DATA REQUIREMENTS:
-- Requires: transaction_id, customer_id, order_amount, transaction_timestamp,
--           transaction_status
-- Improves with: traffic_source, affiliate_id, ip_address, device_fingerprint
--
-- TUNING PARAMETERS:
-- * amount_clustering_threshold — CV of amounts below which to flag (default: 0.05)
-- * min_transactions_to_analyze — minimum transactions to run signal (default: 20)
-- * regularity_window_days      — window to measure timing regularity (default: 30)
-- * min_conversion_rate         — impossibly high conversion rate (default: 85%)
--
-- TYPICAL EXPOSURE: $100,000 — $2,000,000
-- =============================================================================

WITH normalized_transactions AS (
    SELECT
        transaction_id          AS transaction_id,
        customer_id             AS customer_id,
        order_amount            AS order_amount,
        transaction_status      AS transaction_status,
        created_at              AS transaction_timestamp,
        traffic_source          AS traffic_source,          -- expected: VARCHAR (NULL ok)
        affiliate_id            AS affiliate_id,            -- expected: VARCHAR (NULL ok)
        ip_address              AS ip_address,
        device_fingerprint      AS device_fingerprint
    FROM your_orders_table          -- << CHANGE THIS
    WHERE created_at >= DATEADD('day', -30, CURRENT_DATE)
),

thresholds AS (
    SELECT
        0.05    AS amount_clustering_threshold, -- Coefficient of Variation: lower = more clustered
        20      AS min_transactions_to_analyze,
        30      AS regularity_window_days,
        85.0    AS min_conversion_rate          -- Conversion rate above this is suspicious
),

-- Affiliate/source level analysis
source_level_stats AS (
    SELECT
        COALESCE(affiliate_id, traffic_source, 'direct')   AS source_id,
        COUNT(DISTINCT transaction_id)                      AS total_attempts,
        COUNT(DISTINCT CASE WHEN transaction_status = 'succeeded'
                            THEN transaction_id END)        AS successful_transactions,
        SUM(CASE WHEN transaction_status = 'succeeded'
                 THEN order_amount ELSE 0 END)              AS total_successful_gmv,
        COUNT(DISTINCT customer_id)                         AS distinct_customers,
        COUNT(DISTINCT ip_address)                          AS distinct_ips,
        COUNT(DISTINCT device_fingerprint)                  AS distinct_devices,
        -- Amount clustering: low CV = amounts are suspiciously similar
        ROUND(STDDEV(order_amount) / NULLIF(AVG(order_amount), 0), 4)
                                                            AS amount_coefficient_of_variation,
        AVG(order_amount)                                   AS avg_order_amount,
        STDDEV(order_amount)                                AS stddev_order_amount,
        -- Timing regularity: low stddev of inter-transaction gaps = mechanical
        STDDEV(
            DATEDIFF('minute',
                LAG(transaction_timestamp) OVER (
                    PARTITION BY COALESCE(affiliate_id, traffic_source)
                    ORDER BY transaction_timestamp
                ),
                transaction_timestamp
            )
        )                                                   AS timing_stddev_minutes,
        MIN(transaction_timestamp)                          AS first_transaction,
        MAX(transaction_timestamp)                          AS last_transaction
    FROM normalized_transactions
    GROUP BY 1
),

scored_sources AS (
    SELECT
        *,
        ROUND(100.0 * successful_transactions / NULLIF(total_attempts, 0), 1)
                                                            AS conversion_rate_pct,
        ROUND(total_successful_gmv / NULLIF(distinct_customers, 0), 2)
                                                            AS avg_value_per_customer,
        -- Synthetic score: sum of suspicious dimensions
        (CASE WHEN amount_coefficient_of_variation < t.amount_clustering_threshold THEN 1 ELSE 0 END
        + CASE WHEN (100.0 * successful_transactions / NULLIF(total_attempts, 0))
               >= t.min_conversion_rate                     THEN 1 ELSE 0 END
        + CASE WHEN distinct_customers > 10
               AND distinct_ips < distinct_customers * 0.3  THEN 1 ELSE 0 END
        + CASE WHEN timing_stddev_minutes < 5               THEN 1 ELSE 0 END
        )                                                   AS synthetic_dimension_count
    FROM source_level_stats
    CROSS JOIN thresholds t
    WHERE total_attempts >= t.min_transactions_to_analyze
)

SELECT
    source_id,
    total_attempts,
    successful_transactions,
    conversion_rate_pct,
    total_successful_gmv,
    distinct_customers,
    distinct_ips,
    distinct_devices,
    amount_coefficient_of_variation,
    avg_order_amount,
    ROUND(timing_stddev_minutes, 1)                         AS timing_regularity_stddev,
    synthetic_dimension_count,
    first_transaction,
    last_transaction,

    CASE
        WHEN synthetic_dimension_count >= 3                 THEN 'HIGH — Synthetic Pattern Confirmed'
        WHEN synthetic_dimension_count = 2                  THEN 'MEDIUM — Multiple Synthetic Signals'
        WHEN synthetic_dimension_count = 1                  THEN 'LOW — Single Anomaly'
        ELSE 'MONITOR'
    END                                                     AS signal_confidence,

    'Synthetic Transaction Patterns'                        AS signal_name,
    'Source ' || source_id
        || ' shows ' || synthetic_dimension_count::VARCHAR
        || ' synthetic indicators across '
        || total_attempts::VARCHAR || ' transactions ($'
        || ROUND(total_successful_gmv, 0)::VARCHAR || ' GMV). '
        || 'Conversion rate: ' || conversion_rate_pct::VARCHAR
        || '%. Amount CV: ' || amount_coefficient_of_variation::VARCHAR
        || ' (lower = more clustered). '
        || distinct_customers::VARCHAR || ' customers from only '
        || distinct_ips::VARCHAR || ' IPs.'                 AS glass_box_verdict

FROM scored_sources
WHERE synthetic_dimension_count >= 1
ORDER BY synthetic_dimension_count DESC, total_successful_gmv DESC;
