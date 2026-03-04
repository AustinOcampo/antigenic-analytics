-- =============================================================================
-- ANTIGENIC ANALYTICS — SIGNAL: CARD TESTING
-- =============================================================================
-- File:     card_testing_detection.sql
-- Signal:   P03 of 10 — Payments & Gateways
-- Version:  1.0.0
-- License:  Apache 2.0
--
-- WHAT THIS DETECTS:
-- Automated validation of stolen card numbers against your checkout.
-- Fraudsters acquire large batches of card data and need to know which cards
-- are still active before selling or using them. Your checkout becomes the
-- validation tool. They run micro-charges — often $0.00 auth-only, $0.01,
-- or small fixed amounts — in rapid automated sequences from a single IP
-- or device, across many different card numbers.
--
-- BEHAVIORAL TELL:
-- The pattern is unmistakably mechanical: many distinct cards, very small
-- amounts, compressed time window, high decline rate mixed with approvals,
-- single IP or device. No human shops like this. The automated signature
-- is detectable within minutes of it starting — and it often hits your
-- processor fees and chargeback ratios before you notice.
--
-- DATA REQUIREMENTS:
-- Requires: transaction_id, card_fingerprint (or last4+bin), transaction_amount,
--           transaction_status, transaction_timestamp, ip_address
-- Optional: device_fingerprint, customer_id (often absent — testing uses guests)
--
-- TUNING PARAMETERS:
-- * testing_window_minutes   — time window to detect burst (default: 60 min)
-- * min_cards_per_ip         — distinct cards from same IP to flag (default: 5)
-- * max_test_amount          — maximum amount considered a "test charge" (default: $2.00)
-- * min_decline_rate         — decline rate that confirms automated testing (default: 30%)
--
-- TYPICAL EXPOSURE: Processor penalties, chargeback ratio elevation, card scheme fines
-- =============================================================================


-- =============================================================================
-- STEP 1: MAP YOUR COLUMNS AND SET YOUR THRESHOLDS
-- =============================================================================

WITH normalized_transactions AS (

    SELECT
        transaction_id          AS transaction_id,          -- expected: VARCHAR
        -- Card fingerprint: use Stripe's card.fingerprint or construct BIN+last4
        card_fingerprint        AS card_fingerprint,        -- expected: VARCHAR
        transaction_amount      AS transaction_amount,      -- expected: FLOAT
        transaction_status      AS transaction_status,      -- expected: VARCHAR ('succeeded','failed','declined')
        created_at              AS transaction_timestamp,   -- expected: TIMESTAMP_NTZ
        ip_address              AS ip_address,              -- expected: VARCHAR
        device_fingerprint      AS device_fingerprint,      -- expected: VARCHAR (NULL ok)
        customer_id             AS customer_id              -- expected: VARCHAR (NULL ok — guests common)

    FROM your_charges_table         -- << CHANGE THIS (Stripe: charges table)

    WHERE
        created_at >= DATEADD('day', -30, CURRENT_DATE)

),

thresholds AS (
    SELECT
        60      AS testing_window_minutes,      -- Burst detection window
        5       AS min_cards_per_ip,            -- Distinct cards per IP to flag
        2.00    AS max_test_amount,             -- Max charge amount considered a test
        30.0    AS min_decline_rate             -- Minimum decline rate to confirm automation
),


-- =============================================================================
-- STEP 2: ANTIGENIC ANALYTICS DETECTION LOGIC
-- =============================================================================

-- Tag each transaction as a potential test charge
test_candidates AS (
    SELECT
        *,
        CASE WHEN transaction_amount <= t.max_test_amount THEN 1 ELSE 0 END
                                                AS is_test_amount,
        CASE WHEN transaction_status IN ('failed', 'declined', 'card_declined',
                                         'do_not_honor', 'insufficient_funds')
             THEN 1 ELSE 0 END                  AS is_decline
    FROM normalized_transactions
    CROSS JOIN thresholds t
),

-- Build hourly burst windows per IP
ip_hourly_activity AS (
    SELECT
        ip_address,
        DATE_TRUNC('hour', transaction_timestamp)   AS activity_hour,
        COUNT(DISTINCT card_fingerprint)            AS distinct_cards,
        COUNT(DISTINCT transaction_id)              AS total_attempts,
        SUM(is_test_amount)                         AS test_amount_count,
        SUM(is_decline)                             AS decline_count,
        ROUND(100.0 * SUM(is_decline) / NULLIF(COUNT(*), 0), 1)
                                                    AS decline_rate_pct,
        MIN(transaction_timestamp)                  AS window_start,
        MAX(transaction_timestamp)                  AS window_end,
        COUNT(DISTINCT customer_id)                 AS distinct_customers,
        DATEDIFF('minute',
            MIN(transaction_timestamp),
            MAX(transaction_timestamp))             AS burst_duration_minutes
    FROM test_candidates
    GROUP BY 1, 2
),

flagged_ips AS (
    SELECT
        i.*,
        t.min_cards_per_ip,
        t.min_decline_rate,
        CASE
            WHEN i.distinct_cards >= 20
             AND i.decline_rate_pct >= t.min_decline_rate  THEN 'HIGH — Automated Card Testing'
            WHEN i.distinct_cards >= t.min_cards_per_ip
             AND i.test_amount_count >= 3
             AND i.decline_rate_pct >= t.min_decline_rate  THEN 'HIGH — Burst Pattern Confirmed'
            WHEN i.distinct_cards >= t.min_cards_per_ip
             AND i.decline_rate_pct >= t.min_decline_rate  THEN 'MEDIUM — Elevated Card Velocity'
            WHEN i.distinct_cards >= t.min_cards_per_ip    THEN 'LOW — Card Velocity Only'
            ELSE 'LOW'
        END                                         AS signal_confidence
    FROM ip_hourly_activity i
    CROSS JOIN thresholds t
    WHERE
        i.distinct_cards >= t.min_cards_per_ip
)


-- =============================================================================
-- FINAL OUTPUT — GLASS BOX VERDICT
-- =============================================================================

SELECT
    ip_address,
    activity_hour,
    distinct_cards,
    total_attempts,
    test_amount_count,
    decline_count,
    decline_rate_pct,
    burst_duration_minutes,
    distinct_customers,
    window_start,
    window_end,

    signal_confidence,
    'Card Testing'                                  AS signal_name,
    'IP ' || ip_address
        || ' attempted ' || total_attempts::VARCHAR
        || ' transactions using ' || distinct_cards::VARCHAR
        || ' distinct cards within a ' || burst_duration_minutes::VARCHAR
        || '-minute window. Decline rate: ' || decline_rate_pct::VARCHAR
        || '%. ' || test_amount_count::VARCHAR
        || ' charges were under $2.00 (test amount pattern).'
                                                    AS glass_box_verdict

FROM flagged_ips
WHERE signal_confidence IN ('HIGH — Automated Card Testing',
                            'HIGH — Burst Pattern Confirmed',
                            'MEDIUM — Elevated Card Velocity')
ORDER BY signal_confidence, distinct_cards DESC;
