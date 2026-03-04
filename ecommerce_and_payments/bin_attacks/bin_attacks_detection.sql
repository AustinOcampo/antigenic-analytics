-- =============================================================================
-- ANTIGENIC ANALYTICS — SIGNAL: BIN ATTACKS
-- =============================================================================
-- File:     bin_attacks_detection.sql
-- Signal:   P07 of 10 — Payments & Gateways
-- Version:  1.0.0
-- License:  Apache 2.0
--
-- WHAT THIS DETECTS:
-- Sequential enumeration of card numbers within a specific Bank Identification
-- Number (BIN) range against your checkout. A BIN is the first 6 digits of a
-- card number. Fraudsters who acquire a partial card dataset will often attempt
-- to enumerate the remaining digits systematically, using your payment endpoint
-- as the validator. Unlike card testing (which uses already-complete stolen
-- card numbers), BIN attacks show sequential or near-sequential card number
-- patterns within a concentrated BIN range.
--
-- BEHAVIORAL TELL:
-- Natural transaction flow produces random BIN distribution across your
-- customer base. A BIN attack concentrates many attempts within a single
-- BIN prefix, often with sequential last-4 digits, from a small number of
-- IPs, in a compressed time window. The mathematical non-randomness of
-- the card numbers is the signature.
--
-- DATA REQUIREMENTS:
-- Requires: transaction_id, card_bin (first 6 digits), card_last4,
--           transaction_status, transaction_timestamp, ip_address
--
-- TUNING PARAMETERS:
-- * attack_window_minutes    — burst window for BIN concentration (default: 120 min)
-- * min_attempts_per_bin     — attempts within one BIN to flag (default: 10)
-- * min_decline_rate         — decline rate confirming enumeration (default: 50%)
-- * sequential_threshold     — % of last4 values that are sequential (default: 30%)
--
-- TYPICAL EXPOSURE: Processor fines, scheme penalties, fraud liability
-- =============================================================================

WITH normalized_transactions AS (
    SELECT
        transaction_id          AS transaction_id,
        -- BIN: first 6 digits of card number
        card_bin                AS card_bin,                -- expected: VARCHAR(6)
        card_last4              AS card_last4,              -- expected: VARCHAR(4)
        transaction_status      AS transaction_status,
        created_at              AS transaction_timestamp,
        ip_address              AS ip_address
    FROM your_charges_table         -- << CHANGE THIS
    WHERE created_at >= DATEADD('day', -7, CURRENT_DATE)    -- BIN attacks are detected fast
),

thresholds AS (
    SELECT
        120     AS attack_window_minutes,
        10      AS min_attempts_per_bin,
        50.0    AS min_decline_rate,
        30.0    AS sequential_threshold
),

-- BIN-level burst analysis per 2-hour window
bin_windows AS (
    SELECT
        card_bin,
        DATE_TRUNC('hour', transaction_timestamp)           AS window_hour,
        COUNT(DISTINCT transaction_id)                      AS total_attempts,
        COUNT(DISTINCT card_last4)                          AS distinct_last4,
        COUNT(DISTINCT ip_address)                          AS distinct_ips,
        ROUND(100.0 * COUNT(CASE WHEN transaction_status
                IN ('failed','declined','card_declined') THEN 1 END)
            / NULLIF(COUNT(*), 0), 1)                       AS decline_rate_pct,
        MIN(transaction_timestamp)                          AS window_start,
        MAX(transaction_timestamp)                          AS window_end,
        -- Sequential score: stddev of last4 cast as integer
        -- Low stddev = numbers are close together = sequential enumeration
        STDDEV(TRY_CAST(card_last4 AS INTEGER))             AS last4_stddev
    FROM normalized_transactions
    GROUP BY 1, 2
)

SELECT
    card_bin,
    window_hour,
    total_attempts,
    distinct_last4,
    distinct_ips,
    decline_rate_pct,
    ROUND(last4_stddev, 0)                                  AS last4_sequential_score,
    window_start,
    window_end,

    CASE
        WHEN total_attempts >= 50
         AND decline_rate_pct >= t.min_decline_rate
         AND last4_stddev < 500                             THEN 'HIGH — Active BIN Attack'
        WHEN total_attempts >= t.min_attempts_per_bin
         AND decline_rate_pct >= t.min_decline_rate        THEN 'HIGH — BIN Enumeration'
        WHEN total_attempts >= t.min_attempts_per_bin      THEN 'MEDIUM — BIN Concentration'
        ELSE 'LOW'
    END                                                     AS signal_confidence,

    'BIN Attack'                                            AS signal_name,
    'BIN ' || card_bin
        || ' received ' || total_attempts::VARCHAR
        || ' attempts in a 2-hour window from '
        || distinct_ips::VARCHAR || ' IPs. Decline rate: '
        || decline_rate_pct::VARCHAR || '%. '
        || 'Sequential score (lower = more sequential): '
        || ROUND(last4_stddev, 0)::VARCHAR                  AS glass_box_verdict

FROM bin_windows
CROSS JOIN thresholds t
WHERE
    total_attempts >= t.min_attempts_per_bin
    AND decline_rate_pct >= t.min_decline_rate

ORDER BY signal_confidence, total_attempts DESC;
