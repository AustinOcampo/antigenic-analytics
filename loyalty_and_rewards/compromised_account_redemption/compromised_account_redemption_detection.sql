-- =============================================================================
-- ANTIGENIC ANALYTICS — SIGNAL: COMPROMISED ACCOUNT REDEMPTION
-- =============================================================================
-- File:     compromised_account_redemption_detection.sql
-- Signal:   L09 of 10 — Loyalty & Rewards
-- Version:  1.0.0
-- License:  Apache 2.0
--
-- WHAT THIS DETECTS:
-- Loyalty accounts showing sudden redemption activity from devices or
-- geographies never previously associated with the account — the loyalty
-- equivalent of account takeover at checkout. Compromised loyalty accounts
-- are highly valuable targets: accumulated balances can represent hundreds
-- or thousands of dollars in redeemable value, the legitimate owner may
-- not monitor their balance regularly, and points can be redeemed for
-- gift cards or travel that is difficult to reverse.
--
-- BEHAVIORAL TELL:
-- A member who has accessed their account from the same two devices and
-- one city for three years suddenly redeeming their entire balance from
-- a new device in a different country is not taking a vacation. Their
-- account has been compromised. The deviation from established behavioral
-- baseline across multiple dimensions simultaneously is the signature.
--
-- DATA REQUIREMENTS:
-- Requires: member_id, redemption_timestamp, redemption_value,
--           ip_address, device_fingerprint
-- Requires: session history (at least 90 days) to establish baseline
--
-- TUNING PARAMETERS:
-- * baseline_days            — days of history to establish normal behavior (default: 180)
-- * detection_window_days    — recent window to check for deviation (default: 30)
-- * min_balance_redeemed_pct — % of balance redeemed in suspicious event (default: 50%)
--
-- TYPICAL EXPOSURE: $10,000 — $150,000
-- =============================================================================

WITH normalized_redemptions AS (
    SELECT
        member_id               AS member_id,
        redemption_value        AS redemption_value,
        points_redeemed         AS points_redeemed,
        redemption_timestamp    AS redemption_timestamp,
        ip_address              AS ip_address,
        device_fingerprint      AS device_fingerprint,
        geo_country             AS geo_country
    FROM your_redemption_ledger_table   -- << CHANGE THIS
    WHERE redemption_timestamp >= DATEADD('day', -210, CURRENT_DATE)
),

thresholds AS (
    SELECT
        180     AS baseline_days,
        30      AS detection_window_days,
        50.0    AS min_balance_redeemed_pct
),

-- Establish baseline: devices/IPs/countries used in the 180 days BEFORE the detection window
baseline_behavior AS (
    SELECT
        member_id,
        COUNT(DISTINCT device_fingerprint)              AS baseline_device_count,
        COUNT(DISTINCT ip_address)                      AS baseline_ip_count,
        COUNT(DISTINCT geo_country)                     AS baseline_country_count,
        ARRAY_AGG(DISTINCT device_fingerprint)          AS known_devices,
        ARRAY_AGG(DISTINCT ip_address)                  AS known_ips,
        ARRAY_AGG(DISTINCT geo_country)                 AS known_countries,
        SUM(redemption_value)                           AS historical_redemption_value,
        AVG(redemption_value)                           AS avg_historical_redemption
    FROM normalized_redemptions
    CROSS JOIN thresholds t
    WHERE redemption_timestamp < DATEADD('day', -t.detection_window_days, CURRENT_DATE)
    GROUP BY 1
),

-- Recent redemptions in detection window
recent_redemptions AS (
    SELECT r.*
    FROM normalized_redemptions r
    CROSS JOIN thresholds t
    WHERE r.redemption_timestamp >= DATEADD('day', -t.detection_window_days, CURRENT_DATE)
),

-- Join and flag deviations
ato_flags AS (
    SELECT
        r.member_id,
        r.redemption_value,
        r.points_redeemed,
        r.redemption_timestamp,
        r.ip_address,
        r.device_fingerprint,
        r.geo_country,
        b.avg_historical_redemption,
        b.historical_redemption_value,
        b.baseline_device_count,
        CASE WHEN NOT ARRAY_CONTAINS(r.device_fingerprint::VARIANT, b.known_devices)
             THEN 1 ELSE 0 END                          AS is_new_device,
        CASE WHEN NOT ARRAY_CONTAINS(r.ip_address::VARIANT, b.known_ips)
             THEN 1 ELSE 0 END                          AS is_new_ip,
        CASE WHEN r.geo_country IS NOT NULL
              AND NOT ARRAY_CONTAINS(r.geo_country::VARIANT, b.known_countries)
             THEN 1 ELSE 0 END                          AS is_new_country,
        ROUND(r.redemption_value / NULLIF(b.avg_historical_redemption, 0), 2)
                                                        AS value_vs_historical_avg
    FROM recent_redemptions r
    JOIN baseline_behavior b ON r.member_id = b.member_id
)

SELECT
    member_id,
    redemption_value,
    points_redeemed,
    redemption_timestamp,
    device_fingerprint,
    ip_address,
    geo_country,
    avg_historical_redemption,
    is_new_device,
    is_new_ip,
    is_new_country,
    value_vs_historical_avg,
    (is_new_device + is_new_ip + is_new_country)        AS anomaly_dimension_count,

    CASE
        WHEN is_new_country = 1
         AND is_new_device = 1
         AND value_vs_historical_avg >= 3               THEN 'HIGH — ATO Signature'
        WHEN (is_new_device + is_new_ip + is_new_country) >= 2
                                                        THEN 'HIGH — Multi-Dimension Anomaly'
        WHEN is_new_country = 1                         THEN 'MEDIUM — New Country'
        WHEN is_new_device = 1
         AND value_vs_historical_avg >= 2               THEN 'MEDIUM — New Device + High Value'
        ELSE 'LOW'
    END                                                 AS signal_confidence,

    'Compromised Account Redemption'                    AS signal_name,
    'Member ' || member_id
        || ' redeemed $' || ROUND(redemption_value, 0)::VARCHAR
        || ' (' || value_vs_historical_avg::VARCHAR || 'x their historical average) '
        || 'from a '
        || CASE WHEN is_new_device = 1 THEN 'NEW device, ' ELSE 'known device, ' END
        || CASE WHEN is_new_country = 1 THEN 'NEW country (' || geo_country || ').'
                ELSE 'known country.' END               AS glass_box_verdict

FROM ato_flags
WHERE (is_new_device + is_new_ip + is_new_country) >= 1
  AND value_vs_historical_avg >= 1.5

ORDER BY signal_confidence, redemption_value DESC;
