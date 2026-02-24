-- =============================================================================
-- ANTIGENIC ANALYTICS — SIGNAL: FRIENDLY FRAUD — CHARGEBACK ABUSE
-- =============================================================================
-- File:     friendly_fraud_detection.sql
-- Signal:   P05 of 10 — Payments & Gateways
-- Version:  1.0.0
-- License:  Apache 2.0
--
-- WHAT THIS DETECTS:
-- Legitimate customers who have weaponized the dispute process as a
-- shopping strategy. They purchase, receive goods, then file chargebacks
-- claiming non-delivery or unauthorized transaction — effectively getting
-- goods for free while the merchant eats the loss plus chargeback fees.
-- Serial friendly fraudsters are identifiable by their dispute patterns
-- long before your processor flags your chargeback ratio.
--
-- BEHAVIORAL TELL:
-- One chargeback can be legitimate. A customer with 3+ chargebacks across
-- different orders, particularly on high-value items, with confirmed delivery
-- records, is not having bad luck with their card issuer. They have learned
-- the dispute process works in their favor and they are repeating it.
-- The tell is the repeat behavior combined with delivery confirmation.
--
-- DATA REQUIREMENTS:
-- Requires: transaction_id, customer_id, order_amount, transaction_status,
--           dispute_status, dispute_reason, transaction_timestamp
-- Improves with: delivery_confirmation, dispute_filed_timestamp,
--                product_category, shipping_address
--
-- TUNING PARAMETERS:
-- * min_dispute_count        — disputes before flagging as pattern (default: 2)
-- * dispute_rate_threshold   — dispute rate % to flag (default: 15%)
-- * min_disputed_value       — minimum total disputed amount (default: $150)
-- * delivery_gap_days        — days between delivery and dispute = suspicious (default: 5)
--
-- TYPICAL EXPOSURE: $15,000 — $300,000
-- =============================================================================


-- =============================================================================
-- STEP 1: MAP YOUR COLUMNS AND SET YOUR THRESHOLDS
-- =============================================================================

WITH normalized_transactions AS (

    SELECT
        transaction_id          AS transaction_id,          -- expected: VARCHAR
        customer_id             AS customer_id,             -- expected: VARCHAR
        order_amount            AS order_amount,            -- expected: FLOAT
        transaction_status      AS transaction_status,      -- expected: VARCHAR
        dispute_status          AS dispute_status,          -- expected: VARCHAR ('won','lost','pending',NULL)
        dispute_reason          AS dispute_reason,          -- expected: VARCHAR (NULL ok)
        created_at              AS transaction_timestamp,   -- expected: TIMESTAMP_NTZ
        dispute_filed_at        AS dispute_timestamp,       -- expected: TIMESTAMP_NTZ (NULL ok)
        delivered_at            AS delivery_timestamp,      -- expected: TIMESTAMP_NTZ (NULL ok)
        product_category        AS product_category,        -- expected: VARCHAR (NULL ok)
        shipping_address        AS shipping_address         -- expected: VARCHAR (NULL ok)

    FROM your_orders_table          -- << CHANGE THIS

    WHERE created_at >= DATEADD('year', -2, CURRENT_DATE)

),

thresholds AS (
    SELECT
        2       AS min_dispute_count,           -- Disputes before flagging as pattern
        15.0    AS dispute_rate_threshold,      -- Flag if dispute rate exceeds 15%
        150     AS min_disputed_value,          -- Minimum total disputed amount
        5       AS delivery_gap_days            -- Dispute filed within N days of delivery
),


-- =============================================================================
-- STEP 2: ANTIGENIC ANALYTICS DETECTION LOGIC
-- =============================================================================

customer_dispute_stats AS (
    SELECT
        customer_id,
        COUNT(DISTINCT transaction_id)                      AS total_orders,
        SUM(order_amount)                                   AS total_order_value,
        COUNT(DISTINCT CASE WHEN dispute_status IS NOT NULL
                            THEN transaction_id END)        AS dispute_count,
        SUM(CASE WHEN dispute_status IS NOT NULL
                 THEN order_amount ELSE 0 END)              AS total_disputed_amount,
        -- Won disputes = merchant lost = customer got money back
        COUNT(CASE WHEN dispute_status = 'lost' THEN 1 END) AS merchant_lost_count,
        SUM(CASE WHEN dispute_status = 'lost'
                 THEN order_amount ELSE 0 END)              AS confirmed_loss_amount,
        -- Rapid disputes: filed within N days of delivery
        COUNT(CASE WHEN delivery_timestamp IS NOT NULL
                    AND dispute_timestamp IS NOT NULL
                    AND DATEDIFF('day', delivery_timestamp, dispute_timestamp)
                        <= t.delivery_gap_days              THEN 1 END)
                                                            AS rapid_post_delivery_disputes,
        -- Most common dispute reason
        MODE(dispute_reason)                                AS most_common_dispute_reason,
        MIN(transaction_timestamp)                          AS first_order_date,
        MAX(transaction_timestamp)                          AS last_order_date,
        COUNT(DISTINCT shipping_address)                    AS distinct_shipping_addresses
    FROM normalized_transactions
    CROSS JOIN thresholds t
    GROUP BY 1
),

scored_customers AS (
    SELECT
        *,
        ROUND(100.0 * dispute_count / NULLIF(total_orders, 0), 1)
                                                            AS dispute_rate_pct,
        ROUND(100.0 * confirmed_loss_amount
            / NULLIF(total_disputed_amount, 0), 1)          AS merchant_loss_rate_pct
    FROM customer_dispute_stats
)


-- =============================================================================
-- FINAL OUTPUT — GLASS BOX VERDICT
-- =============================================================================

SELECT
    customer_id,
    total_orders,
    total_order_value,
    dispute_count,
    dispute_rate_pct,
    total_disputed_amount,
    confirmed_loss_amount,
    merchant_loss_rate_pct,
    rapid_post_delivery_disputes,
    most_common_dispute_reason,
    distinct_shipping_addresses,
    first_order_date,
    last_order_date,

    CASE
        WHEN dispute_count >= 4
         AND merchant_loss_rate_pct >= 50                  THEN 'HIGH — Serial Friendly Fraudster'
        WHEN dispute_count >= t.min_dispute_count
         AND dispute_rate_pct >= t.dispute_rate_threshold
         AND rapid_post_delivery_disputes >= 1             THEN 'HIGH — Pattern + Rapid Disputes'
        WHEN dispute_count >= t.min_dispute_count
         AND dispute_rate_pct >= t.dispute_rate_threshold  THEN 'MEDIUM — Repeat Disputer'
        ELSE 'LOW'
    END                                                     AS signal_confidence,

    'Friendly Fraud — Chargeback Abuse'                     AS signal_name,
    'Customer ' || customer_id
        || ' has filed ' || dispute_count::VARCHAR
        || ' disputes across ' || total_orders::VARCHAR
        || ' orders (' || dispute_rate_pct::VARCHAR
        || '% dispute rate), totaling $'
        || ROUND(total_disputed_amount, 0)::VARCHAR
        || ' disputed. Merchant confirmed losses: $'
        || ROUND(confirmed_loss_amount, 0)::VARCHAR
        || '. Most common reason: ' || COALESCE(most_common_dispute_reason, 'unspecified')
                                                            AS glass_box_verdict

FROM scored_customers
CROSS JOIN thresholds t
WHERE
    dispute_count >= t.min_dispute_count
    AND total_disputed_amount >= t.min_disputed_value
    AND dispute_rate_pct >= t.dispute_rate_threshold

ORDER BY signal_confidence, confirmed_loss_amount DESC;
