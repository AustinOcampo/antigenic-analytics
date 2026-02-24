-- =============================================================================
-- ANTIGENIC ANALYTICS — SIGNAL: TRIANGULATION FRAUD
-- =============================================================================
-- File:     triangulation_fraud_detection.sql
-- Signal:   P06 of 10 — Payments & Gateways
-- Version:  1.0.0
-- License:  Apache 2.0
--
-- WHAT THIS DETECTS:
-- A three-party scheme where a fraudster operates a storefront (often on
-- a marketplace), collects real payments from real buyers, then fulfills
-- those orders using stolen credit cards to purchase from your store.
-- Your store ships real goods. The real buyer receives their order.
-- The stolen cardholder files a chargeback. You lose the goods AND the money.
--
-- BEHAVIORAL TELL:
-- Triangulation fraud leaves a specific fingerprint on the receiving end:
-- orders with mismatched billing/shipping details, shipping to addresses
-- that appear in multiple orders from different customers, large quantities
-- of single SKUs (resale pattern), and billing addresses that frequently
-- fail AVS checks while shipping addresses are confirmed valid.
--
-- DATA REQUIREMENTS:
-- Requires: transaction_id, customer_id, order_amount, billing_address,
--           shipping_address, transaction_timestamp, avs_result
-- Improves with: quantity_per_sku, product_category, card_fingerprint
--
-- TUNING PARAMETERS:
-- * min_orders_to_address    — orders to same shipping address from diff customers (default: 3)
-- * avs_mismatch_rate        — AVS failure rate to flag (default: 40%)
-- * min_order_amount         — minimum order value to analyze (default: $50)
--
-- TYPICAL EXPOSURE: $50,000 — $500,000
-- =============================================================================

WITH normalized_transactions AS (
    SELECT
        transaction_id          AS transaction_id,
        customer_id             AS customer_id,
        order_amount            AS order_amount,
        LOWER(TRIM(billing_address))
                                AS billing_address,
        LOWER(TRIM(shipping_address))
                                AS shipping_address,
        created_at              AS transaction_timestamp,
        avs_result              AS avs_result,              -- expected: VARCHAR ('Y','N','A','Z', etc.)
        card_fingerprint        AS card_fingerprint
    FROM your_orders_table          -- << CHANGE THIS
    WHERE
        created_at >= DATEADD('day', -90, CURRENT_DATE)
        AND transaction_status NOT IN ('failed','declined')
        AND order_amount >= 50
),

thresholds AS (
    SELECT
        3       AS min_orders_to_address,
        40.0    AS avs_mismatch_rate,
        50      AS min_order_amount
),

-- Shipping addresses receiving orders from multiple distinct customers
shared_shipping AS (
    SELECT
        shipping_address,
        COUNT(DISTINCT customer_id)                 AS distinct_customers,
        COUNT(DISTINCT transaction_id)              AS total_orders,
        SUM(order_amount)                           AS total_order_value,
        COUNT(DISTINCT card_fingerprint)            AS distinct_cards_used,
        -- AVS mismatch: billing != shipping AND avs not fully matched
        ROUND(100.0 * COUNT(CASE WHEN billing_address != shipping_address
                                  AND avs_result NOT IN ('Y','D','M')
                                  THEN 1 END) / NULLIF(COUNT(*), 0), 1)
                                                    AS avs_mismatch_rate_pct
    FROM normalized_transactions
    GROUP BY 1
)

SELECT
    shipping_address,
    distinct_customers,
    total_orders,
    total_order_value,
    distinct_cards_used,
    avs_mismatch_rate_pct,

    CASE
        WHEN distinct_customers >= 5
         AND avs_mismatch_rate_pct >= t.avs_mismatch_rate  THEN 'HIGH — Drop Address + AVS Failure'
        WHEN distinct_customers >= t.min_orders_to_address
         AND avs_mismatch_rate_pct >= t.avs_mismatch_rate  THEN 'HIGH — Triangulation Pattern'
        WHEN distinct_customers >= t.min_orders_to_address THEN 'MEDIUM — Shared Drop Address'
        ELSE 'LOW'
    END                                                     AS signal_confidence,

    'Triangulation Fraud'                                   AS signal_name,
    shipping_address
        || ' received orders from ' || distinct_customers::VARCHAR
        || ' distinct customers using ' || distinct_cards_used::VARCHAR
        || ' distinct cards. Total value: $' || ROUND(total_order_value, 0)::VARCHAR
        || '. AVS mismatch rate: ' || avs_mismatch_rate_pct::VARCHAR || '%.'
                                                            AS glass_box_verdict

FROM shared_shipping
CROSS JOIN thresholds t
WHERE
    distinct_customers >= t.min_orders_to_address
ORDER BY signal_confidence, total_order_value DESC;
