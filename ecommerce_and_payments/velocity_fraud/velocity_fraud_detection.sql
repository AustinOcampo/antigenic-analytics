-- =============================================================================
-- ANTIGENIC ANALYTICS — SIGNAL: VELOCITY FRAUD
-- =============================================================================
-- File:     velocity_fraud_detection.sql
-- Signal:   P04 of 10 — Payments & Gateways
-- Version:  1.0.0
-- License:  Apache 2.0
--
-- WHAT THIS DETECTS:
-- Burst transaction patterns where a single identity — customer, card,
-- device, or IP — attempts to maximize purchases within a short window
-- before fraud controls respond. Velocity fraudsters know that most
-- systems have approval windows before blocks are applied. They exploit
-- that window aggressively, often purchasing high-value or easily resellable
-- goods in rapid succession.
--
-- BEHAVIORAL TELL:
-- A legitimate customer who places 3 orders in 20 minutes is unusual
-- but explainable. A customer who places 8 orders across 4 different
-- shipping addresses in 45 minutes using 3 different cards is a velocity
-- attack. The combination of spend acceleration + address variance +
-- card switching is the unmistakable fingerprint.
--
-- DATA REQUIREMENTS:
-- Requires: transaction_id, customer_id, order_amount, transaction_timestamp,
--           transaction_status, card_fingerprint
-- Improves with: shipping_address, ip_address, device_fingerprint
--
-- TUNING PARAMETERS:
-- * velocity_window_minutes  — burst detection window (default: 60 min)
-- * min_transactions         — minimum transactions in window to flag (default: 3)
-- * min_burst_spend          — minimum spend in window to flag (default: $500)
-- * max_address_variance     — distinct shipping addresses in burst (default: 2)
--
-- TYPICAL EXPOSURE: $50,000 — $1,000,000
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
        created_at              AS transaction_timestamp,   -- expected: TIMESTAMP_NTZ
        card_fingerprint        AS card_fingerprint,        -- expected: VARCHAR
        shipping_address        AS shipping_address,        -- expected: VARCHAR (NULL ok)
        ip_address              AS ip_address,              -- expected: VARCHAR (NULL ok)
        device_fingerprint      AS device_fingerprint       -- expected: VARCHAR (NULL ok)

    FROM your_orders_table          -- << CHANGE THIS

    WHERE
        created_at >= DATEADD('day', -30, CURRENT_DATE)
        AND transaction_status NOT IN ('failed', 'declined')

),

thresholds AS (
    SELECT
        60      AS velocity_window_minutes,     -- Burst detection window in minutes
        3       AS min_transactions,            -- Minimum transactions in window
        500     AS min_burst_spend,             -- Minimum burst spend to flag
        2       AS max_address_variance         -- Distinct shipping addresses in burst
),


-- =============================================================================
-- STEP 2: ANTIGENIC ANALYTICS DETECTION LOGIC
-- =============================================================================

-- Self-join to build transaction windows per customer
transaction_windows AS (
    SELECT
        a.customer_id,
        a.transaction_id                            AS anchor_transaction_id,
        a.transaction_timestamp                     AS window_start,
        DATEADD('minute', t.velocity_window_minutes, a.transaction_timestamp)
                                                    AS window_end,
        t.velocity_window_minutes,
        t.min_transactions,
        t.min_burst_spend,
        t.max_address_variance
    FROM normalized_transactions a
    CROSS JOIN thresholds t
),

-- Find all transactions within each window
windowed_transactions AS (
    SELECT
        w.customer_id,
        w.anchor_transaction_id,
        w.window_start,
        w.window_end,
        w.velocity_window_minutes,
        w.min_transactions,
        w.min_burst_spend,
        w.max_address_variance,
        COUNT(DISTINCT tx.transaction_id)           AS tx_count,
        SUM(tx.order_amount)                        AS burst_spend,
        COUNT(DISTINCT tx.card_fingerprint)         AS distinct_cards,
        COUNT(DISTINCT tx.shipping_address)         AS distinct_addresses,
        COUNT(DISTINCT tx.ip_address)               AS distinct_ips,
        MIN(tx.transaction_timestamp)               AS first_tx_time,
        MAX(tx.transaction_timestamp)               AS last_tx_time,
        DATEDIFF('minute',
            MIN(tx.transaction_timestamp),
            MAX(tx.transaction_timestamp))          AS actual_burst_minutes
    FROM transaction_windows w
    JOIN normalized_transactions tx
        ON  w.customer_id = tx.customer_id
        AND tx.transaction_timestamp BETWEEN w.window_start AND w.window_end
    GROUP BY 1, 2, 3, 4, 5, 6, 7, 8
),

-- Keep only the highest-spend window per customer (dedup)
best_window_per_customer AS (
    SELECT *,
        ROW_NUMBER() OVER (
            PARTITION BY customer_id
            ORDER BY burst_spend DESC
        ) AS rn
    FROM windowed_transactions
    WHERE
        tx_count >= min_transactions
        AND burst_spend >= min_burst_spend
),

flagged_customers AS (
    SELECT
        customer_id,
        burst_spend,
        tx_count,
        distinct_cards,
        distinct_addresses,
        distinct_ips,
        actual_burst_minutes,
        velocity_window_minutes,
        first_tx_time,
        last_tx_time,
        CASE
            WHEN distinct_cards >= 3
             AND distinct_addresses >= max_address_variance  THEN 'HIGH — Multi-Card Multi-Address'
            WHEN tx_count >= 5
             AND burst_spend >= 1000                         THEN 'HIGH — High Velocity Burst'
            WHEN distinct_cards >= 2
             OR distinct_addresses >= max_address_variance   THEN 'MEDIUM — Velocity + Variance'
            ELSE 'LOW'
        END                                                 AS signal_confidence
    FROM best_window_per_customer
    WHERE rn = 1
)


-- =============================================================================
-- FINAL OUTPUT — GLASS BOX VERDICT
-- =============================================================================

SELECT
    customer_id,
    burst_spend,
    tx_count                                            AS transactions_in_window,
    distinct_cards,
    distinct_addresses                                  AS distinct_shipping_addresses,
    distinct_ips,
    actual_burst_minutes                                AS burst_duration_minutes,
    first_tx_time,
    last_tx_time,

    signal_confidence,
    'Velocity Fraud'                                    AS signal_name,
    'Customer ' || customer_id
        || ' placed ' || tx_count::VARCHAR
        || ' orders totaling $' || ROUND(burst_spend, 0)::VARCHAR
        || ' in ' || actual_burst_minutes::VARCHAR
        || ' minutes. Used ' || distinct_cards::VARCHAR
        || ' distinct cards and ' || distinct_addresses::VARCHAR
        || ' shipping addresses.'                       AS glass_box_verdict

FROM flagged_customers
ORDER BY signal_confidence, burst_spend DESC;
