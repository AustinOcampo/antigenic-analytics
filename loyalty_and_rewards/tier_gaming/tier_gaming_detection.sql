-- =============================================================================
-- ANTIGENIC ANALYTICS — SIGNAL: TIER GAMING
-- =============================================================================
-- File:     tier_gaming_detection.sql
-- Signal:   L05 of 10 — Loyalty & Rewards
-- Version:  1.0.0
-- License:  Apache 2.0
--
-- WHAT THIS DETECTS:
-- Members who manufacture activity specifically to cross a tier threshold
-- then go dormant immediately after achieving the higher tier status.
-- Tier benefits — free shipping, lounge access, upgrade eligibility —
-- are designed to reward genuinely loyal customers. Tier gamers exploit
-- the threshold mechanics without providing the ongoing revenue the
-- tier was designed to reward.
--
-- BEHAVIORAL TELL:
-- Legitimate tier advancement is followed by continued engagement at the
-- new tier level. Tier gamers show a sharp activity spike immediately
-- before the qualification period ends, cross the threshold, then drop
-- to near-zero activity. The cliff-edge spend pattern is unmistakable.
--
-- DATA REQUIREMENTS:
-- Requires: member_id, accrual_timestamp, points_earned, tier_status,
--           tier_qualified_date, qualification_period_end
--
-- TUNING PARAMETERS:
-- * pre_cutoff_window_days   — days before period end to measure spike (default: 30)
-- * post_tier_dormancy_days  — days after tier award with low activity (default: 60)
-- * activity_drop_threshold  — % drop in activity to flag dormancy (default: 80%)
--
-- TYPICAL EXPOSURE: $20,000 — $300,000 (value of tier benefits granted)
-- =============================================================================

WITH normalized_accruals AS (
    SELECT
        member_id               AS member_id,
        points_earned           AS points_earned,
        transaction_amount      AS transaction_amount,
        accrual_timestamp       AS accrual_timestamp,
        tier_status             AS tier_status,
        tier_qualified_date     AS tier_qualified_date      -- expected: DATE (NULL if not yet qualified)
    FROM your_accrual_ledger_table  -- << CHANGE THIS
    WHERE accrual_timestamp >= DATEADD('year', -2, CURRENT_DATE)
),

thresholds AS (
    SELECT
        30      AS pre_cutoff_window_days,
        60      AS post_tier_dormancy_days,
        80.0    AS activity_drop_threshold_pct
),

-- Pre-tier activity: spend in the 30 days before tier qualification
pre_tier_activity AS (
    SELECT
        a.member_id,
        MAX(a.tier_qualified_date)                      AS tier_qualified_date,
        SUM(CASE WHEN a.accrual_timestamp >= DATEADD('day',
                      -t.pre_cutoff_window_days, MAX(a.tier_qualified_date))
                  AND a.accrual_timestamp < MAX(a.tier_qualified_date)
                  THEN a.points_earned ELSE 0 END)       AS pre_tier_points,
        SUM(CASE WHEN a.accrual_timestamp >= DATEADD('day',
                      -t.pre_cutoff_window_days, MAX(a.tier_qualified_date))
                  AND a.accrual_timestamp < MAX(a.tier_qualified_date)
                  THEN a.transaction_amount ELSE 0 END)  AS pre_tier_spend
    FROM normalized_accruals a
    CROSS JOIN thresholds t
    WHERE a.tier_qualified_date IS NOT NULL
    GROUP BY 1
),

-- Post-tier activity: spend in the 60 days after tier qualification
post_tier_activity AS (
    SELECT
        a.member_id,
        SUM(CASE WHEN a.accrual_timestamp > p.tier_qualified_date
                  AND a.accrual_timestamp <= DATEADD('day',
                      t.post_tier_dormancy_days, p.tier_qualified_date)
                  THEN a.points_earned ELSE 0 END)       AS post_tier_points,
        SUM(CASE WHEN a.accrual_timestamp > p.tier_qualified_date
                  AND a.accrual_timestamp <= DATEADD('day',
                      t.post_tier_dormancy_days, p.tier_qualified_date)
                  THEN a.transaction_amount ELSE 0 END)  AS post_tier_spend
    FROM normalized_accruals a
    JOIN pre_tier_activity p ON a.member_id = p.member_id
    CROSS JOIN thresholds t
    GROUP BY 1
)

SELECT
    p.member_id,
    p.tier_qualified_date,
    p.pre_tier_spend,
    p.pre_tier_points,
    pt.post_tier_spend,
    pt.post_tier_points,
    ROUND(100.0 * (1 - pt.post_tier_spend / NULLIF(p.pre_tier_spend, 0)), 1)
                                                        AS activity_drop_pct,
    CASE
        WHEN pt.post_tier_spend <= p.pre_tier_spend * 0.1
         AND p.pre_tier_spend >= 200                    THEN 'HIGH — Cliff-Edge Dormancy'
        WHEN pt.post_tier_spend <= p.pre_tier_spend * 0.2  THEN 'MEDIUM — Sharp Activity Drop'
        ELSE 'LOW'
    END                                                 AS signal_confidence,
    'Tier Gaming'                                       AS signal_name,
    'Member ' || p.member_id
        || ' spent $' || ROUND(p.pre_tier_spend, 0)::VARCHAR
        || ' in the 30 days before tier qualification, then only $'
        || ROUND(pt.post_tier_spend, 0)::VARCHAR
        || ' in the 60 days after — an '
        || ROUND(100.0 * (1 - pt.post_tier_spend / NULLIF(p.pre_tier_spend, 0)), 1)::VARCHAR
        || '% drop in activity.'                        AS glass_box_verdict

FROM pre_tier_activity p
JOIN post_tier_activity pt ON p.member_id = pt.member_id
CROSS JOIN thresholds t
WHERE
    ROUND(100.0 * (1 - pt.post_tier_spend / NULLIF(p.pre_tier_spend, 0)), 1)
        >= t.activity_drop_threshold_pct
    AND p.pre_tier_spend >= 100

ORDER BY signal_confidence, activity_drop_pct DESC;
