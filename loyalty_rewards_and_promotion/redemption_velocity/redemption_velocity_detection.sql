-- =============================================================================
-- ANTIGENIC ANALYTICS — SIGNAL: REDEMPTION VELOCITY ABUSE
-- =============================================================================
-- File:     redemption_velocity_detection.sql
-- Signal:   L02 of 10 — Loyalty & Rewards
-- Version:  1.0.0
-- License:  Apache 2.0
--
-- WHAT THIS DETECTS:
-- Members redeeming points in bursts that are timed, sized, or structured
-- to stay below program cancellation or review thresholds. This is the
-- loyalty equivalent of sub-threshold batching in AP fraud. Programs that
-- auto-cancel accounts above a certain redemption velocity get gamed by
-- fraudsters who split redemptions across sessions, days, or accounts
-- to stay below the trigger — collectively extracting far more than
-- the threshold was designed to allow.
--
-- BEHAVIORAL TELL:
-- Organic redemption behavior is irregular — members redeem when they
-- have enough points and want something. Velocity abusers redeem in
-- suspiciously consistent amounts, often just below a known program
-- limit, in compressed time windows. The precision is the tell.
--
-- DATA REQUIREMENTS:
-- Requires: member_id, points_redeemed, redemption_value,
--           redemption_timestamp, redemption_type
--
-- TUNING PARAMETERS:
-- * redemption_threshold_pts   — program's per-event review limit (default: 10,000 pts)
-- * velocity_window_days       — rolling window for burst detection (default: 30)
-- * min_redemptions_in_window  — minimum redemptions to flag pattern (default: 3)
-- * sub_threshold_tolerance    — how close to limit counts as "near-threshold" (default: 10%)
--
-- TYPICAL EXPOSURE: $15,000 — $150,000
-- =============================================================================

WITH normalized_redemptions AS (

    SELECT
        member_id               AS member_id,               -- expected: VARCHAR
        points_redeemed         AS points_redeemed,         -- expected: FLOAT
        redemption_value        AS redemption_value,        -- expected: FLOAT ($ value of redemption)
        redemption_timestamp    AS redemption_timestamp,    -- expected: TIMESTAMP_NTZ
        redemption_type         AS redemption_type          -- expected: VARCHAR ('gift_card','travel','merch')

    FROM your_redemption_ledger_table   -- << CHANGE THIS

    WHERE redemption_timestamp >= DATEADD('day', -90, CURRENT_DATE)

),

thresholds AS (
    SELECT
        10000   AS redemption_threshold_pts,    -- Per-event review/cancel limit in your program
        30      AS velocity_window_days,
        3       AS min_redemptions_in_window,
        10.0    AS sub_threshold_tolerance_pct  -- Within 10% of threshold = near-threshold
),

-- Tag redemptions as near-threshold
tagged_redemptions AS (
    SELECT
        r.*,
        t.redemption_threshold_pts,
        t.velocity_window_days,
        t.min_redemptions_in_window,
        t.sub_threshold_tolerance_pct,
        CASE
            WHEN r.points_redeemed <= t.redemption_threshold_pts
             AND r.points_redeemed >= t.redemption_threshold_pts
                 * (1 - t.sub_threshold_tolerance_pct / 100.0)
            THEN 1 ELSE 0
        END                                             AS is_near_threshold
    FROM normalized_redemptions r
    CROSS JOIN thresholds t
    WHERE r.points_redeemed < t.redemption_threshold_pts
),

-- Rolling window aggregation per member
member_velocity AS (
    SELECT
        a.member_id,
        a.redemption_timestamp                          AS anchor_timestamp,
        COUNT(DISTINCT b.redemption_timestamp)          AS redemptions_in_window,
        SUM(b.points_redeemed)                          AS total_pts_in_window,
        SUM(b.redemption_value)                         AS total_value_in_window,
        SUM(b.is_near_threshold)                        AS near_threshold_count,
        MIN(b.redemption_timestamp)                     AS window_start,
        MAX(b.redemption_timestamp)                     AS window_end,
        DATEDIFF('day',
            MIN(b.redemption_timestamp),
            MAX(b.redemption_timestamp))                AS window_span_days,
        MAX(a.redemption_threshold_pts)                 AS redemption_threshold_pts,
        MAX(a.min_redemptions_in_window)                AS min_redemptions_in_window
    FROM tagged_redemptions a
    JOIN tagged_redemptions b
        ON  a.member_id = b.member_id
        AND b.redemption_timestamp BETWEEN a.redemption_timestamp
            AND DATEADD('day', a.velocity_window_days, a.redemption_timestamp)
    GROUP BY 1, 2
),

best_window AS (
    SELECT *,
        ROW_NUMBER() OVER (
            PARTITION BY member_id
            ORDER BY total_pts_in_window DESC
        ) AS rn
    FROM member_velocity
    WHERE redemptions_in_window >= min_redemptions_in_window
)

SELECT
    member_id,
    redemptions_in_window,
    total_pts_in_window,
    total_value_in_window,
    near_threshold_count,
    ROUND(100.0 * near_threshold_count / NULLIF(redemptions_in_window, 0), 1)
                                                        AS near_threshold_rate_pct,
    window_start,
    window_end,
    window_span_days,
    redemption_threshold_pts,

    CASE
        WHEN near_threshold_count >= 3
         AND redemptions_in_window >= 4                THEN 'HIGH — Structured Below Threshold'
        WHEN near_threshold_count >= 2                 THEN 'MEDIUM — Near-Threshold Pattern'
        WHEN redemptions_in_window >= 5                THEN 'MEDIUM — High Velocity'
        ELSE 'LOW'
    END                                                 AS signal_confidence,

    'Redemption Velocity Abuse'                         AS signal_name,
    'Member ' || member_id
        || ' made ' || redemptions_in_window::VARCHAR
        || ' redemptions totaling ' || ROUND(total_pts_in_window, 0)::VARCHAR
        || ' points ($' || ROUND(total_value_in_window, 0)::VARCHAR
        || ') over ' || window_span_days::VARCHAR || ' days. '
        || near_threshold_count::VARCHAR
        || ' redemptions were within 10% of the '
        || redemption_threshold_pts::VARCHAR
        || '-point program threshold.'                  AS glass_box_verdict

FROM best_window
WHERE rn = 1
ORDER BY signal_confidence, total_value_in_window DESC;
