-- =============================================================================
-- ANTIGENIC ANALYTICS — SIGNAL: ACCOUNT TAKEOVER AT CHECKOUT
-- =============================================================================
-- File:     account_takeover_detection.sql
-- Signal:   P08 of 10 — Payments & Gateways
-- Version:  1.0.0
-- License:  Apache 2.0
--
-- WHAT THIS DETECTS:
-- Hijacked customer accounts used to make rapid high-value purchases,
-- typically shipping to addresses not previously associated with the account.
-- ATO fraudsters acquire credentials through phishing or breach data, log in,
-- immediately change shipping address or add a new payment method, and
-- place orders before the legitimate account holder notices.
--
-- BEHAVIORAL TELL:
-- The legitimate account holder has a behavioral history — devices they use,
-- locations they ship to, purchase amounts they typically make. The fraudster
-- deviates from all of it simultaneously: new device, new IP geography,
-- new shipping address, higher-than-normal order value, and speed.
-- The combination of deviation signals across multiple dimensions at the
-- same time is the ATO fingerprint.
--
-- DATA REQUIREMENTS:
-- Requires: transaction_id, customer_id, order_amount, transaction_timestamp,
--           shipping_address, ip_address
-- Improves with: device_fingerprint, login_timestamp, password_changed_at,
--               payment_method_added_at
--
-- TUNING PARAMETERS:
-- * new_address_flag         — order to address never used before (binary signal)
-- * ato_window_hours         — hours post-login to flag unusual activity (default: 24)
-- * value_spike_multiplier   — order amount vs customer avg to flag (default: 3x)
-- * min_order_history        — minimum prior orders to establish baseline (default: 2)
--
-- TYPICAL EXPOSURE: $20,000 — $200,000
-- =============================================================================

WITH normalized_transactions AS (
    SELECT
        transaction_id          AS transaction_id,
        customer_id             AS customer_id,
        order_amount            AS order_amount,
        created_at              AS transaction_timestamp,
        LOWER(TRIM(shipping_address))
                                AS shipping_address,
        ip_address              AS ip_address,
        device_fingerprint      AS device_fingerprint
    FROM your_orders_table          -- << CHANGE THIS
    WHERE
        created_at >= DATEADD('year', -2, CURRENT_DATE)
        AND transaction_status NOT IN ('failed','declined')
),

thresholds AS (
    SELECT
        3.0     AS value_spike_multiplier,      -- Flag if order is 3x customer's normal average
        2       AS min_order_history,           -- Minimum prior orders to establish baseline
        24      AS ato_window_hours             -- Hours to look back for suspicious session
),

-- Customer historical baseline
customer_baseline AS (
    SELECT
        customer_id,
        AVG(order_amount)                               AS avg_order_amount,
        COUNT(DISTINCT shipping_address)                AS historic_address_count,
        COUNT(DISTINCT ip_address)                      AS historic_ip_count,
        COUNT(DISTINCT device_fingerprint)              AS historic_device_count,
        COUNT(DISTINCT transaction_id)                  AS total_historic_orders,
        -- Collect historical addresses for new-address detection
        ARRAY_AGG(DISTINCT shipping_address)            AS known_addresses
    FROM normalized_transactions
    WHERE transaction_timestamp < DATEADD('day', -1, CURRENT_DATE) -- exclude last 24h from baseline
    GROUP BY 1
),

-- Recent transactions (last 24 hours) to check against baseline
recent_orders AS (
    SELECT *
    FROM normalized_transactions
    WHERE transaction_timestamp >= DATEADD('hour', -24, CURRENT_TIMESTAMP)
),

-- Join recent to baseline and flag deviations
ato_candidates AS (
    SELECT
        r.transaction_id,
        r.customer_id,
        r.order_amount,
        r.transaction_timestamp,
        r.shipping_address,
        r.ip_address,
        r.device_fingerprint,
        b.avg_order_amount,
        b.total_historic_orders,
        b.historic_address_count,
        t.value_spike_multiplier,
        t.min_order_history,
        ROUND(r.order_amount / NULLIF(b.avg_order_amount, 0), 2)
                                                        AS order_value_multiple,
        -- New address flag: shipping address not in customer's history
        CASE WHEN NOT ARRAY_CONTAINS(r.shipping_address::VARIANT, b.known_addresses)
             THEN 1 ELSE 0 END                          AS is_new_address,
        -- Value spike flag
        CASE WHEN r.order_amount >= t.value_spike_multiplier * b.avg_order_amount
             THEN 1 ELSE 0 END                          AS is_value_spike
    FROM recent_orders r
    JOIN customer_baseline b ON r.customer_id = b.customer_id
    CROSS JOIN thresholds t
    WHERE b.total_historic_orders >= t.min_order_history
)

SELECT
    customer_id,
    transaction_id,
    order_amount,
    avg_order_amount                                    AS customer_historical_avg,
    order_value_multiple,
    is_new_address,
    is_value_spike,
    shipping_address,
    ip_address,
    transaction_timestamp,
    total_historic_orders,

    CASE
        WHEN is_new_address = 1 AND is_value_spike = 1  THEN 'HIGH — New Address + Value Spike'
        WHEN is_new_address = 1 AND order_value_multiple >= 2
                                                        THEN 'HIGH — New Address + Elevated Value'
        WHEN is_value_spike = 1                         THEN 'MEDIUM — Value Spike Only'
        WHEN is_new_address = 1                         THEN 'MEDIUM — New Address Only'
        ELSE 'LOW'
    END                                                 AS signal_confidence,

    'Account Takeover at Checkout'                      AS signal_name,
    'Customer ' || customer_id
        || ' placed $' || ROUND(order_amount, 0)::VARCHAR
        || ' order (' || order_value_multiple::VARCHAR || 'x their $'
        || ROUND(avg_order_amount, 0)::VARCHAR || ' average). '
        || CASE WHEN is_new_address = 1 THEN 'Shipping to a NEW address never used on this account. '
                ELSE 'Shipping to known address. ' END
        || 'Based on ' || total_historic_orders::VARCHAR || ' prior orders.'
                                                        AS glass_box_verdict

FROM ato_candidates
WHERE is_new_address = 1 OR is_value_spike = 1
ORDER BY signal_confidence, order_amount DESC;
